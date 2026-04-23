"""feroxbuster tool service — async wrapper around the `feroxbuster` binary.

Stateless. Core orchestrator forwards engine
``ctx.call_tool('feroxbuster', {...})`` calls here AFTER scope-checking the
target URL. This service runs ``feroxbuster -u <url> --no-state -q`` and
returns the line-based stdout.

Endpoints:
    GET  /healthz          liveness + feroxbuster version
    POST /invoke           FeroxbusterRequest -> FeroxbusterResult

Output:
    feroxbuster prints one discovered URL per line on stdout (`-q` mode strips
    banner/progress). We return raw stdout — engines split lines.

Security: same model as nuclei — `_SAFE_URL_RE` enforces a well-formed http(s)
URL, subprocess invoked list-form, no leading-dash flag smuggling possible.
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


class FeroxbusterRequest(BaseModel):
    model_config = {"extra": "forbid"}

    target: str = Field(..., min_length=8, max_length=2048)
    timeout_s: int = Field(default=300, ge=10, le=1800)

    @field_validator("target")
    @classmethod
    def _check_target(cls, v: str) -> str:
        if not _SAFE_URL_RE.match(v):
            raise ValueError(
                f"target {v!r} is not a well-formed http(s) URL "
                f"(or contains disallowed characters)"
            )
        return v


class FeroxbusterResult(BaseModel):
    target: str
    command: str
    returncode: int
    stdout: str
    """One discovered URL per line."""
    stderr: str
    duration_ms: int
    success: bool


async def _run_feroxbuster(target: str, timeout_s: int) -> FeroxbusterResult:
    cmd = ["feroxbuster", "-u", target, "--no-state", "-q"]
    logger.info("feroxbuster run target=%s timeout=%ss", target, timeout_s)
    started = asyncio.get_event_loop().time()

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        return FeroxbusterResult(
            target=target,
            command=" ".join(cmd),
            returncode=127,
            stdout="",
            stderr=f"feroxbuster binary not found: {exc}",
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
        return FeroxbusterResult(
            target=target,
            command=" ".join(cmd),
            returncode=124,
            stdout="",
            stderr=f"timeout after {timeout_s}s",
            duration_ms=timeout_s * 1000,
            success=False,
        )

    rc = proc.returncode if proc.returncode is not None else -1
    return FeroxbusterResult(
        target=target,
        command=" ".join(cmd),
        returncode=rc,
        stdout=stdout_b.decode("utf-8", errors="replace"),
        stderr=stderr_b.decode("utf-8", errors="replace"),
        duration_ms=int((asyncio.get_event_loop().time() - started) * 1000),
        success=(rc == 0),
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    fx_path = shutil.which("feroxbuster")
    app.state.feroxbuster_path = fx_path
    if fx_path is None:
        logger.warning("feroxbuster binary not in PATH — /invoke will return 127")
    else:
        logger.info("feroxbuster available at %s", fx_path)
    yield


app = FastAPI(title="trustchain feroxbuster", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    fx_path = (
        getattr(app.state, "feroxbuster_path", None) or shutil.which("feroxbuster")
    )
    return {"status": "ok", "feroxbuster": fx_path or "missing"}


@app.post("/invoke", response_model=FeroxbusterResult)
async def invoke(req: FeroxbusterRequest) -> FeroxbusterResult:
    return await _run_feroxbuster(req.target, req.timeout_s)
