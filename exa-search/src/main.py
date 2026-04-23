"""exa-search tool service — thin async wrapper over the Exa.ai search API.

Engines call ``ctx.call_tool("exa-search", {query: ..., num_results: 20})``
when they need web search results — primary consumer is the Phase 3
``weakness-gather-exa`` engine which feeds CVE / vuln info to an LLM.

Architectural notes:
  * Exa API key lives in this service's env (EXA_API_KEY), NOT in
    ctx.secrets. Engines see only the search results, never the key.
    This follows the same "platform-infra secret" pattern as tool
    binaries (nmap/nuclei/...) that live in tool-svc images.
  * The tool's ``request`` field is ``query``, NOT ``url``/``target``/
    ``host`` — so core's generic scope gate (Codex P0-2) naturally
    bypasses this tool. Intentional: Exa searches the public web,
    not the target; target scope is irrelevant.
  * Upstream rate limit (429) surfaces as ``success=false`` + a
    stderr note. Engines handle via the same ``ToolUnavailable``
    soft-fail path as other tools.

Endpoints:
    GET  /healthz         liveness + EXA_API_KEY present check
    POST /invoke          ExaSearchRequest → ExaSearchResult
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any, Literal

import httpx
from fastapi import FastAPI
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


EXA_API_URL = "https://api.exa.ai/search"
EXA_ENV_KEY = "EXA_API_KEY"


class ExaSearchRequest(BaseModel):
    model_config = {"extra": "forbid"}

    query: str = Field(..., min_length=1, max_length=2000)
    num_results: int = Field(default=10, ge=1, le=50)
    search_type: Literal["auto", "keyword", "neural"] = "auto"
    include_domains: list[str] | None = None
    exclude_domains: list[str] | None = None
    timeout_s: int = Field(default=30, ge=5, le=120)


class ExaSearchResult(BaseModel):
    query: str
    results: list[dict[str, Any]]
    """Exa's raw result entries — engines parse as they see fit. Each
    entry typically has: ``title`` / ``url`` / ``text`` (LLM-friendly
    excerpt) / ``score`` / ``publishedDate``."""
    num_results_requested: int
    num_results_returned: int
    duration_ms: int
    success: bool
    error: str | None = None
    """Populated when success=false: human-readable reason (rate limit /
    auth failure / network error / malformed response)."""


# --- Exa HTTP plumbing ----------------------------------------------------


async def _call_exa(
    req: ExaSearchRequest, client: httpx.AsyncClient, api_key: str
) -> ExaSearchResult:
    body: dict[str, Any] = {
        "query": req.query,
        "numResults": req.num_results,
        "type": req.search_type,
    }
    if req.include_domains:
        body["includeDomains"] = req.include_domains
    if req.exclude_domains:
        body["excludeDomains"] = req.exclude_domains

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    started = time.monotonic()
    try:
        resp = await client.post(
            EXA_API_URL, json=body, headers=headers, timeout=req.timeout_s
        )
    except httpx.TimeoutException as exc:
        return ExaSearchResult(
            query=req.query,
            results=[],
            num_results_requested=req.num_results,
            num_results_returned=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            success=False,
            error=f"timeout after {req.timeout_s}s: {exc}",
        )
    except httpx.HTTPError as exc:
        return ExaSearchResult(
            query=req.query,
            results=[],
            num_results_requested=req.num_results,
            num_results_returned=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            success=False,
            error=f"transport error: {exc}",
        )

    duration_ms = int((time.monotonic() - started) * 1000)

    if resp.status_code == 429:
        return ExaSearchResult(
            query=req.query,
            results=[],
            num_results_requested=req.num_results,
            num_results_returned=0,
            duration_ms=duration_ms,
            success=False,
            error="exa rate limit (429)",
        )
    if resp.status_code in (401, 403):
        # Surfaced as success=false rather than 500 so engine soft-fail
        # handles it. Operator sees via logs that the platform key is bad.
        logger.warning("exa auth failed: %s %s", resp.status_code, resp.text[:200])
        return ExaSearchResult(
            query=req.query,
            results=[],
            num_results_requested=req.num_results,
            num_results_returned=0,
            duration_ms=duration_ms,
            success=False,
            error=f"exa auth failed ({resp.status_code}) — check EXA_API_KEY on exa-search-svc",
        )
    if resp.status_code >= 400:
        return ExaSearchResult(
            query=req.query,
            results=[],
            num_results_requested=req.num_results,
            num_results_returned=0,
            duration_ms=duration_ms,
            success=False,
            error=f"exa returned {resp.status_code}: {resp.text[:200]}",
        )

    try:
        payload = resp.json()
    except Exception as exc:
        return ExaSearchResult(
            query=req.query,
            results=[],
            num_results_requested=req.num_results,
            num_results_returned=0,
            duration_ms=duration_ms,
            success=False,
            error=f"exa returned non-JSON: {exc}",
        )

    results = payload.get("results") or []
    return ExaSearchResult(
        query=req.query,
        results=results,
        num_results_requested=req.num_results,
        num_results_returned=len(results),
        duration_ms=duration_ms,
        success=True,
    )


# --- App ------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Single shared httpx.AsyncClient — connection pooling across calls.
    app.state.client = httpx.AsyncClient(timeout=30.0)
    app.state.exa_key = os.environ.get(EXA_ENV_KEY, "").strip()
    if not app.state.exa_key:
        logger.warning(
            "%s not set — every /invoke will return success=false (auth failure)",
            EXA_ENV_KEY,
        )
    else:
        logger.info("exa-search ready (key prefix=%s***)", app.state.exa_key[:4])
    try:
        yield
    finally:
        await app.state.client.aclose()


app = FastAPI(title="trustchain exa-search", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    # Reports whether EXA_API_KEY is configured, but NOT the key itself.
    # Unconfigured = service still healthy (/invoke will soft-fail); lets
    # operators start the compose stack before filling in the env var.
    key = getattr(app.state, "exa_key", None) or os.environ.get(EXA_ENV_KEY, "")
    return {"status": "ok", "exa_key_configured": bool(key)}


@app.post("/invoke", response_model=ExaSearchResult)
async def invoke(req: ExaSearchRequest) -> ExaSearchResult:
    client: httpx.AsyncClient = app.state.client
    api_key: str = app.state.exa_key or ""
    if not api_key:
        # No key = immediate soft-fail. Engine sees success=false; lab
        # admin sees it in the health endpoint.
        return ExaSearchResult(
            query=req.query,
            results=[],
            num_results_requested=req.num_results,
            num_results_returned=0,
            duration_ms=0,
            success=False,
            error=f"{EXA_ENV_KEY} not configured on exa-search-svc container",
        )
    return await _call_exa(req, client, api_key)
