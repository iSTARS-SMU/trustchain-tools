"""whatweb tool service — async wrapper around WhatWeb (Ruby).

Stateless. Runs ``whatweb --color=never --log-json=- <url>`` and returns
the JSON output. Engines parse the JSON to extract tech / version signals
for TechFingerprint.

Endpoints:
    GET  /healthz         liveness + whatweb path
    POST /invoke          WhatwebRequest → WhatwebResult

Security: `target` must be a well-formed http(s) URL (same regex pattern
as nuclei / feroxbuster wrappers — argv injection impossible since URL
must start with http(s):// and not a leading dash).
"""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


_SAFE_URL_RE = re.compile(
    r"^https?://[A-Za-z0-9._\-~:/\[\]?#@!$&'()*+,;=%]+$"
)

# ANSI escape codes (whatweb emits color even with --color=never in some
# edge cases; strip defensively as the LLMAppSec original did).
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class WhatwebRequest(BaseModel):
    model_config = {"extra": "forbid"}

    target: str = Field(..., min_length=8, max_length=2048)
    timeout_s: int = Field(default=300, ge=10, le=900)

    @field_validator("target")
    @classmethod
    def _check_target(cls, v: str) -> str:
        if not _SAFE_URL_RE.match(v):
            raise ValueError(
                f"target {v!r} is not a well-formed http(s) URL"
            )
        return v


class WhatwebResult(BaseModel):
    target: str
    command: str
    returncode: int
    stdout: str
    """JSON lines (one per plugin hit). Engines parse with json.loads per line."""
    stderr: str
    duration_ms: int
    success: bool


async def _run_whatweb(target: str, timeout_s: int) -> WhatwebResult:
    cmd = ["whatweb", "--color=never", "--log-json=-", target]
    logger.info("whatweb run target=%s timeout=%ss", target, timeout_s)
    started = asyncio.get_event_loop().time()

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        return WhatwebResult(
            target=target,
            command=" ".join(cmd),
            returncode=127,
            stdout="",
            stderr=f"whatweb binary not found: {exc}",
            duration_ms=int((asyncio.get_event_loop().time() - started) * 1000),
            success=False,
        )

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=timeout_s
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return WhatwebResult(
            target=target,
            command=" ".join(cmd),
            returncode=124,
            stdout="",
            stderr=f"timeout after {timeout_s}s",
            duration_ms=timeout_s * 1000,
            success=False,
        )

    rc = proc.returncode if proc.returncode is not None else -1
    stdout = _ANSI_RE.sub("", stdout_b.decode("utf-8", errors="replace"))
    stderr = stderr_b.decode("utf-8", errors="replace")
    return WhatwebResult(
        target=target,
        command=" ".join(cmd),
        returncode=rc,
        stdout=stdout,
        stderr=stderr,
        duration_ms=int((asyncio.get_event_loop().time() - started) * 1000),
        success=(rc == 0),
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    path = shutil.which("whatweb")
    app.state.whatweb_path = path
    if path is None:
        logger.warning("whatweb binary not in PATH — /invoke will return rc=127")
    else:
        logger.info("whatweb available at %s", path)
    yield


app = FastAPI(title="trustchain whatweb", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    path = getattr(app.state, "whatweb_path", None) or shutil.which("whatweb")
    return {"status": "ok", "whatweb": path or "missing"}


@app.post("/invoke", response_model=WhatwebResult)
async def invoke(req: WhatwebRequest) -> WhatwebResult:
    return await _run_whatweb(req.target, req.timeout_s)
