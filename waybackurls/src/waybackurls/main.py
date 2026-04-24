"""waybackurls — thin wrapper over the `waybackurls` Go binary.

Fetches URLs for a domain from the Wayback Machine (web.archive.org)
CDX index. Faster + narrower than gau (archive.org only), but
complementary: some endpoints only show up in one source or the other.

Port of LLMAppSec/services/external-tools/waybackurls (77 LOC). Same
binary, synchronous /invoke instead of task_id polling.
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


class WaybackurlsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(
        description="Hostname or domain. waybackurls accepts both; hostname is the intended use.",
        min_length=1,
        max_length=256,
    )
    timeout_sec: float = Field(
        default=180.0,
        gt=0,
        le=600,
        description="Hard cap on the waybackurls subprocess. Archive queries can be slow for popular hosts.",
    )
    max_urls: int = Field(
        default=5000,
        ge=1,
        le=50000,
        description="Cap on the number of URLs returned; waybackurls itself doesn't truncate.",
    )


class WaybackurlsResponse(BaseModel):
    success: bool
    target: str = ""
    urls: list[str] = Field(default_factory=list)
    total_found: int = 0
    truncated: bool = False
    returncode: int = 0
    duration_ms: int = 0
    error: str = ""


app = FastAPI(
    title="trustchain-tool-waybackurls",
    version="0.1.0",
    description="waybackurls Go binary wrapper. Returns Wayback Machine historical URLs for a target.",
)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/schema")
async def schema() -> dict[str, Any]:
    return {
        "tool_id": "waybackurls",
        "version": "0.1.0",
        "request_schema": WaybackurlsRequest.model_json_schema(),
        "response_schema": WaybackurlsResponse.model_json_schema(),
    }


@app.post("/invoke", response_model=WaybackurlsResponse)
async def invoke(body: WaybackurlsRequest) -> WaybackurlsResponse:
    started = time.perf_counter()
    # waybackurls reads targets from stdin (unlike gau which takes an arg).
    try:
        proc = await asyncio.create_subprocess_exec(
            "waybackurls",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "LANG": "C"},
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(input=body.target.encode() + b"\n"),
                timeout=body.timeout_sec,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return WaybackurlsResponse(
                success=False,
                target=body.target,
                error="timeout",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
    except FileNotFoundError:
        return WaybackurlsResponse(
            success=False,
            target=body.target,
            error="waybackurls CLI not installed on tool image",
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    stdout = (stdout_b or b"").decode("utf-8", errors="replace")
    stderr = (stderr_b or b"").decode("utf-8", errors="replace")

    urls = [line.strip() for line in stdout.splitlines() if line.strip()]
    total = len(urls)
    truncated = total > body.max_urls
    if truncated:
        urls = urls[: body.max_urls]

    return WaybackurlsResponse(
        success=proc.returncode == 0,
        target=body.target,
        urls=urls,
        total_found=total,
        truncated=truncated,
        returncode=proc.returncode or 0,
        duration_ms=int((time.perf_counter() - started) * 1000),
        error=stderr[:500] if proc.returncode != 0 else "",
    )
