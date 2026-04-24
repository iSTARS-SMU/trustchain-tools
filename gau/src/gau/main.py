"""gau — thin wrapper over the `gau` (Get All URLs) Go binary.

Discovers historical URLs for a target host from AlienVault OTX,
Wayback Machine, and CommonCrawl. Useful for recon: finds endpoints
that existed in past versions of the site but aren't in the current
link graph — classic source of forgotten admin paths, abandoned API
versions, etc.

Port of LLMAppSec/services/external-tools/gau (76 LOC). Same binary,
same subprocess pattern; synchronous /invoke instead of task_id
polling.

Binary install: via multi-stage Dockerfile, `go install
github.com/lc/gau/v2/cmd/gau@latest` in a builder stage, copied into
the runtime image.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)


class GauRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(
        description="Hostname or domain. gau accepts both; hostname (no scheme) is the intended use.",
        min_length=1,
        max_length=256,
    )
    timeout_sec: float = Field(
        default=300.0,
        gt=0,
        le=900,
        description="Hard cap on the gau subprocess. Archive queries can be slow for popular hosts; 300s default is generous.",
    )
    max_urls: int = Field(
        default=5000,
        ge=1,
        le=50000,
        description="Cap on the number of URLs returned to the caller. gau itself doesn't truncate; this is our own safety net against mass memory use for popular hosts.",
    )


class GauResponse(BaseModel):
    success: bool
    target: str = ""
    urls: list[str] = Field(default_factory=list)
    total_found: int = Field(default=0, description="Raw count before max_urls truncation.")
    truncated: bool = False
    returncode: int = 0
    duration_ms: int = 0
    error: str = ""


app = FastAPI(
    title="trustchain-tool-gau",
    version="0.1.0",
    description="gau Go binary wrapper. Returns historical URLs for a target from web archives.",
)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/schema")
async def schema() -> dict[str, Any]:
    return {
        "tool_id": "gau",
        "version": "0.1.0",
        "request_schema": GauRequest.model_json_schema(),
        "response_schema": GauResponse.model_json_schema(),
    }


@app.post("/invoke", response_model=GauResponse)
async def invoke(body: GauRequest) -> GauResponse:
    started = time.perf_counter()
    try:
        proc = await asyncio.create_subprocess_exec(
            "gau",
            body.target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "LANG": "C"},
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=body.timeout_sec
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return GauResponse(
                success=False,
                target=body.target,
                error="timeout",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
    except FileNotFoundError:
        return GauResponse(
            success=False,
            target=body.target,
            error="gau CLI not installed on tool image",
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    stdout = (stdout_b or b"").decode("utf-8", errors="replace")
    stderr = (stderr_b or b"").decode("utf-8", errors="replace")

    urls = [line.strip() for line in stdout.splitlines() if line.strip()]
    total = len(urls)
    truncated = total > body.max_urls
    if truncated:
        urls = urls[: body.max_urls]

    return GauResponse(
        success=proc.returncode == 0,
        target=body.target,
        urls=urls,
        total_found=total,
        truncated=truncated,
        returncode=proc.returncode or 0,
        duration_ms=int((time.perf_counter() - started) * 1000),
        error=stderr[:500] if proc.returncode != 0 else "",
    )
