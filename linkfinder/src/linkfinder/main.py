"""linkfinder — thin wrapper over the LinkFinder Python tool.

Parses JavaScript files for URLs / API endpoints embedded in the
source. Complements HTML-based crawlers (feroxbuster, webstructure):
modern SPAs have many endpoints that only show up as string literals
inside bundled JS — neither wordlist brute-force nor HTML link
extraction finds them.

Port of LLMAppSec/services/external-tools/linkfinder (80 LOC). Same
LinkFinder binary cloned at image build time; synchronous /invoke
instead of task_id polling.

LinkFinder CLI: `linkfinder.py -i <url_or_file> -o cli` prints one
discovered endpoint per line.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)


# Path the Dockerfile clones LinkFinder into. Override via env for local dev.
LINKFINDER_PATH = os.environ.get("LINKFINDER_PATH", "/opt/linkfinder/linkfinder.py")


class LinkfinderRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(
        description="URL of a JS file, a page that loads JS, or a filesystem path. LinkFinder -i accepts all three.",
        min_length=1,
        max_length=2048,
    )
    timeout_sec: float = Field(
        default=300.0,
        gt=0,
        le=900,
        description="Hard cap on the LinkFinder subprocess. Big SPA bundles can take minutes.",
    )
    max_endpoints: int = Field(
        default=2000,
        ge=1,
        le=20000,
        description="Cap on the number of endpoints returned. LinkFinder itself doesn't truncate.",
    )


class LinkfinderResponse(BaseModel):
    success: bool
    target: str = ""
    endpoints: list[str] = Field(default_factory=list)
    total_found: int = 0
    truncated: bool = False
    returncode: int = 0
    duration_ms: int = 0
    error: str = ""


app = FastAPI(
    title="trustchain-tool-linkfinder",
    version="0.1.0",
    description="LinkFinder wrapper. Extracts URL / endpoint strings from JavaScript source.",
)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/schema")
async def schema() -> dict[str, Any]:
    return {
        "tool_id": "linkfinder",
        "version": "0.1.0",
        "request_schema": LinkfinderRequest.model_json_schema(),
        "response_schema": LinkfinderResponse.model_json_schema(),
    }


@app.post("/invoke", response_model=LinkfinderResponse)
async def invoke(body: LinkfinderRequest) -> LinkfinderResponse:
    started = time.perf_counter()
    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            LINKFINDER_PATH,
            "-i",
            body.target,
            "-o",
            "cli",
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
            return LinkfinderResponse(
                success=False,
                target=body.target,
                error="timeout",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
    except FileNotFoundError:
        return LinkfinderResponse(
            success=False,
            target=body.target,
            error=f"LinkFinder not found at {LINKFINDER_PATH} (check LINKFINDER_PATH env)",
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    stdout = (stdout_b or b"").decode("utf-8", errors="replace")
    stderr = (stderr_b or b"").decode("utf-8", errors="replace")

    # LinkFinder -o cli prints endpoints one per line; filter empty lines
    # + the occasional banner/status line (heuristic: endpoints contain
    # "/" or start with http).
    endpoints = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if "/" in stripped or stripped.startswith(("http://", "https://")):
            endpoints.append(stripped)

    total = len(endpoints)
    truncated = total > body.max_endpoints
    if truncated:
        endpoints = endpoints[: body.max_endpoints]

    return LinkfinderResponse(
        success=proc.returncode == 0,
        target=body.target,
        endpoints=endpoints,
        total_found=total,
        truncated=truncated,
        returncode=proc.returncode or 0,
        duration_ms=int((time.perf_counter() - started) * 1000),
        error=stderr[:500] if proc.returncode != 0 else "",
    )
