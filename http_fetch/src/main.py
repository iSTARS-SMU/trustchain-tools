"""http_fetch tool service — engine egress proxy.

Stateless HTTP wrapper. Core orchestrator forwards engine `ctx.fetch()` calls
here AFTER scope-checking; this service performs the real outbound request and
returns a structured ``HttpFetchResult``.

Endpoints:
    GET  /healthz          liveness
    POST /invoke           HttpFetchRequest -> HttpFetchResult

The service does NOT see run_id / stage_attempt_id / callback tokens — those
stay in core. Per spec §12, tools are pure compute; auth + scope live in core.

Body size handling:
    - ``max_response_bytes`` (default 5 MB) caps the in-memory read.
    - First 4 KB returned as ``body_preview`` for quick engine reading.
    - When the response exceeds the cap, ``truncated=true``. The body is NOT
      uploaded as an artifact from this service (artifact upload requires a
      callback token that lives in core). Engines that need the full body must
      raise ``max_response_bytes`` or ask core to spill the artifact in a later
      iteration. See spec §16.2.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from trustchain_contracts import HttpFetchRequest, HttpFetchResult

logger = logging.getLogger(__name__)

PREVIEW_BYTES = 4 * 1024


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Single shared httpx.AsyncClient — connection pooling across requests.
    app.state.client = httpx.AsyncClient(
        follow_redirects=False,  # we do redirects manually, capped by httpx config below
        timeout=30.0,
    )
    try:
        yield
    finally:
        await app.state.client.aclose()


app = FastAPI(title="trustchain http_fetch", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/invoke", response_model=HttpFetchResult)
async def invoke(req: HttpFetchRequest) -> HttpFetchResult | JSONResponse:
    client: httpx.AsyncClient = app.state.client

    body_kwargs: dict = {}
    if isinstance(req.body, (bytes, str)):
        body_kwargs["content"] = req.body
    elif isinstance(req.body, dict):
        body_kwargs["json"] = req.body

    # Stream the response so we can stop reading at max_response_bytes + 1
    # without ever buffering the full body in memory. Without this, a
    # malicious / runaway target could OOM the tool service by serving a
    # multi-GB body — the model's max_response_bytes only controls the
    # returned shape, not the actual read. (Codex P2.)
    raw = bytearray()
    truncated = False
    try:
        async with client.stream(
            req.method,
            req.url,
            headers=req.headers or None,
            follow_redirects=req.follow_redirects,
            **body_kwargs,
        ) as resp:
            async for chunk in resp.aiter_bytes(chunk_size=64 * 1024):
                if not chunk:
                    continue
                remaining = req.max_response_bytes - len(raw)
                if remaining <= 0:
                    truncated = True
                    break
                if len(chunk) > remaining:
                    raw.extend(chunk[:remaining])
                    truncated = True
                    break
                raw.extend(chunk)
            # Capture status / headers / final_url BEFORE leaving the context
            # — once aclose() runs they're still valid, but be explicit.
            status_code = resp.status_code
            headers = {k: v for k, v in resp.headers.items()}
            final_url = str(resp.url)
    except httpx.TimeoutException as exc:
        logger.info("http_fetch timeout url=%s: %s", req.url, exc)
        return JSONResponse(
            status_code=504,
            content={"error": "TARGET_UNREACHABLE", "detail": f"timeout: {exc}"},
        )
    except httpx.HTTPError as exc:
        logger.info("http_fetch error url=%s: %s", req.url, exc)
        return JSONResponse(
            status_code=502,
            content={"error": "TARGET_UNREACHABLE", "detail": str(exc)},
        )

    preview = bytes(raw[:PREVIEW_BYTES])
    try:
        preview_str = preview.decode("utf-8", errors="replace")
    except Exception:
        preview_str = repr(preview)

    return HttpFetchResult(
        status_code=status_code,
        headers=headers,
        body_preview=preview_str,
        body_artifact_ref=None,
        truncated=truncated,
        final_url=final_url,
    )
