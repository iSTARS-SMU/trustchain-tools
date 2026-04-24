"""nvd-search — HTTP wrapper over the NVD 2.0 REST API.

Used by the weakness-gather-exa engine (Phase 3.1) to look up CVE records
for a given CPE / product / keyword. NVD is authoritative for CVE metadata;
we complement Exa's web-search-based results with NVD's structured data
(CVSS scores, affected versions, references) for higher-signal weakness
candidates (see doc/TODO.md `Choice 5 — dual-source weakness_gather`).

Endpoint used:
    GET https://services.nvd.nist.gov/rest/json/cves/2.0

Rate limits (from NVD docs):
    * Unauthenticated: 5 requests per rolling 30 seconds
    * With NVD_API_KEY: 50 requests per rolling 30 seconds
We surface 429s as a soft-fail (success=false + clear error) so the
engine can decide to back off or fall through to Exa only.

Config:
    env NVD_API_KEY (optional)   — passed through in x-apiKey header
                                   when set; bumps the rate limit 10×
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, Literal

import httpx
from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_ENV_KEY = "NVD_API_KEY"


class NVDSearchRequest(BaseModel):
    """Input shape for /invoke. All fields optional — NVD treats absent
    filters as "unconstrained on that axis", but at least ONE of
    cpe_name / keyword_search / cve_id must be set (the wrapper rejects
    payloads that would return the entire CVE database)."""

    model_config = ConfigDict(extra="forbid")

    cpe_name: str | None = Field(
        default=None,
        description='CPE 2.3 formatted string, e.g. "cpe:2.3:a:django:django:4.2.0:*:*:*:*:*:*:*". '
        "NVD matches CVEs whose Configuration entries contain this CPE.",
        max_length=256,
    )
    keyword_search: str | None = Field(
        default=None,
        description="Free-text CVE description search. Lower precision than "
        "cpe_name but useful when CPE isn't known.",
        max_length=256,
    )
    cve_id: str | None = Field(
        default=None,
        pattern=r"^CVE-\d{4}-\d{4,}$",
        description="Exact CVE ID lookup, e.g. 'CVE-2024-12345'.",
    )
    cvss_v3_severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = Field(
        default=None,
        description="Filter by CVSSv3 severity band. NVD supports exact-match on this field.",
    )
    pub_start_date: str | None = Field(
        default=None,
        description="ISO8601 timestamp lower bound (inclusive) on CVE publish date, "
        'e.g. "2024-01-01T00:00:00.000" (NVD expects milliseconds).',
        max_length=32,
    )
    pub_end_date: str | None = Field(
        default=None,
        description="ISO8601 timestamp upper bound on CVE publish date.",
        max_length=32,
    )
    results_per_page: int = Field(
        default=20,
        ge=1,
        le=2000,
        description="NVD allows up to 2000 per page; we cap at 2000 and default "
        "to 20 to keep engine-side prompt budgets manageable.",
    )
    timeout_s: float = Field(
        default=30.0,
        gt=0.0,
        le=120.0,
        description="Per-request timeout against NVD. NVD is normally fast but "
        "can lag under load.",
    )


class NVDSearchResult(BaseModel):
    """Output shape from /invoke. Every invoke returns this same shape —
    failures are signaled via ``success=false`` + ``error`` rather than
    HTTP status codes, so the engine's ctx.call_tool sees success=true
    at the HTTP layer regardless."""

    request_echo: dict[str, Any]
    total_results: int = 0
    """NVD's reported total (may exceed len(vulnerabilities) if paginated)."""
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    """Raw NVD `vulnerabilities[]` pass-through. Engine extracts what it wants."""
    duration_ms: int = 0
    success: bool = True
    error: str | None = None


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Create a shared httpx client + record the NVD API key (if any)."""
    app.state.client = httpx.AsyncClient(timeout=30.0)
    app.state.nvd_key = os.environ.get(NVD_ENV_KEY, "").strip()
    if app.state.nvd_key:
        logger.info("nvd-search: NVD_API_KEY present (rate limit ×10)")
    else:
        logger.info("nvd-search: no NVD_API_KEY; unauthenticated rate limits apply")
    try:
        yield
    finally:
        await app.state.client.aclose()


app = FastAPI(title="trustchain-tool-nvd-search", lifespan=_lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    return {
        "status": "ok",
        "tool": "nvd-search",
        "nvd_api_key_configured": bool(
            getattr(app.state, "nvd_key", "") or os.environ.get(NVD_ENV_KEY, "").strip()
        ),
    }


@app.post("/invoke", response_model=NVDSearchResult)
async def invoke(req: NVDSearchRequest) -> NVDSearchResult:
    """Translate the request into NVD 2.0 query params and call it.

    NVD rejects queries with no filters (would return the entire DB), so
    we require at least one of cpe_name / keyword_search / cve_id. Other
    fields are narrower filters that compose with those.
    """
    if not (req.cpe_name or req.keyword_search or req.cve_id):
        return NVDSearchResult(
            request_echo=req.model_dump(exclude_none=True),
            success=False,
            error=(
                "need at least one of cpe_name / keyword_search / cve_id "
                "(NVD refuses unfiltered queries that would return the whole DB)"
            ),
        )

    return await _call_nvd(req)


async def _call_nvd(req: NVDSearchRequest) -> NVDSearchResult:
    import time as _time

    params: dict[str, Any] = {"resultsPerPage": req.results_per_page}
    if req.cpe_name:
        params["cpeName"] = req.cpe_name
    if req.keyword_search:
        params["keywordSearch"] = req.keyword_search
    if req.cve_id:
        params["cveId"] = req.cve_id
    if req.cvss_v3_severity:
        params["cvssV3Severity"] = req.cvss_v3_severity
    if req.pub_start_date:
        params["pubStartDate"] = req.pub_start_date
    if req.pub_end_date:
        params["pubEndDate"] = req.pub_end_date

    headers: dict[str, str] = {"Accept": "application/json"}
    nvd_key = getattr(app.state, "nvd_key", "") or os.environ.get(NVD_ENV_KEY, "").strip()
    if nvd_key:
        headers["apiKey"] = nvd_key

    started = _time.monotonic()
    client: httpx.AsyncClient = app.state.client

    try:
        resp = await client.get(
            NVD_API_URL, params=params, headers=headers, timeout=req.timeout_s
        )
    except httpx.TimeoutException as exc:
        return _soft_fail(req, started, f"timeout after {req.timeout_s}s: {exc}")
    except httpx.HTTPError as exc:
        return _soft_fail(req, started, f"transport error: {exc}")

    if resp.status_code == 429:
        return _soft_fail(
            req,
            started,
            "rate limit hit (NVD 429). "
            + (
                "Even with NVD_API_KEY, 50/30s cap applies."
                if nvd_key
                else f"Set {NVD_ENV_KEY} to raise the cap 5→50 per 30s."
            ),
        )
    if resp.status_code in (401, 403):
        return _soft_fail(
            req,
            started,
            f"auth failed ({resp.status_code}). Check {NVD_ENV_KEY} — "
            f"NVD response: {resp.text[:200]}",
        )
    if resp.status_code == 404:
        # NVD returns 404 for unknown cveId — treat as empty result, not error.
        return NVDSearchResult(
            request_echo=req.model_dump(exclude_none=True),
            duration_ms=int((_time.monotonic() - started) * 1000),
            vulnerabilities=[],
            total_results=0,
            success=True,
        )
    if resp.status_code >= 500:
        return _soft_fail(
            req, started, f"NVD server error ({resp.status_code}): {resp.text[:200]}"
        )
    if resp.status_code >= 400:
        return _soft_fail(
            req, started, f"NVD client error ({resp.status_code}): {resp.text[:200]}"
        )

    try:
        data = resp.json()
    except ValueError:
        return _soft_fail(
            req, started, f"non-JSON response from NVD: {resp.text[:200]}"
        )

    if not isinstance(data, dict):
        return _soft_fail(
            req, started, f"unexpected NVD response shape (not a JSON object)"
        )

    return NVDSearchResult(
        request_echo=req.model_dump(exclude_none=True),
        total_results=int(data.get("totalResults", 0)),
        vulnerabilities=list(data.get("vulnerabilities", [])),
        duration_ms=int((_time.monotonic() - started) * 1000),
        success=True,
    )


def _soft_fail(req: NVDSearchRequest, started_monotonic: float, msg: str) -> NVDSearchResult:
    import time as _time

    return NVDSearchResult(
        request_echo=req.model_dump(exclude_none=True),
        duration_ms=int((_time.monotonic() - started_monotonic) * 1000),
        success=False,
        error=msg,
    )
