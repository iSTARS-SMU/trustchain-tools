"""wafw00f tool service — async wrapper around the `wafw00f` python binary.

Stateless. Runs ``wafw00f -a -f json -o - <url>`` and returns the JSON
payload in stdout. Engines parse to extract WAF identity (if any).

Endpoints:
    GET  /healthz        liveness + wafw00f path
    POST /invoke         Wafw00fRequest → Wafw00fResult

Security: `target` gated by the same http(s)-URL regex as the other URL
tools (nuclei / feroxbuster / whatweb). wafw00f reject raw hostnames
anyway — it derives the URL internally and expects http/https prefix.
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


class Wafw00fRequest(BaseModel):
    model_config = {"extra": "forbid"}

    target: str = Field(..., min_length=8, max_length=2048)
    find_all: bool = Field(
        default=True,
        description="Pass `-a` to keep probing after first WAF match (more complete).",
    )
    timeout_s: int = Field(default=120, ge=10, le=600)

    @field_validator("target")
    @classmethod
    def _check_target(cls, v: str) -> str:
        if not _SAFE_URL_RE.match(v):
            raise ValueError(
                f"target {v!r} is not a well-formed http(s) URL"
            )
        return v


class Wafw00fResult(BaseModel):
    target: str
    command: str
    returncode: int
    stdout: str
    """wafw00f JSON output (via `-f json -o -`). Engines `json.loads()`."""
    stderr: str
    duration_ms: int
    success: bool


async def _run_wafw00f(target: str, find_all: bool, timeout_s: int) -> Wafw00fResult:
    cmd = ["wafw00f"]
    if find_all:
        cmd.append("-a")
    cmd.extend(["-f", "json", "-o", "-", target])
    logger.info("wafw00f run target=%s timeout=%ss", target, timeout_s)
    started = asyncio.get_event_loop().time()

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        return Wafw00fResult(
            target=target,
            command=" ".join(cmd),
            returncode=127,
            stdout="",
            stderr=f"wafw00f binary not found: {exc}",
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
        return Wafw00fResult(
            target=target,
            command=" ".join(cmd),
            returncode=124,
            stdout="",
            stderr=f"timeout after {timeout_s}s",
            duration_ms=timeout_s * 1000,
            success=False,
        )

    rc = proc.returncode if proc.returncode is not None else -1
    return Wafw00fResult(
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
    path = shutil.which("wafw00f")
    app.state.wafw00f_path = path
    if path is None:
        logger.warning("wafw00f binary not in PATH — /invoke will return rc=127")
    else:
        logger.info("wafw00f available at %s", path)
    yield


app = FastAPI(title="trustchain wafw00f", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    path = getattr(app.state, "wafw00f_path", None) or shutil.which("wafw00f")
    return {"status": "ok", "wafw00f": path or "missing"}


@app.post("/invoke", response_model=Wafw00fResult)
async def invoke(req: Wafw00fRequest) -> Wafw00fResult:
    return await _run_wafw00f(req.target, req.find_all, req.timeout_s)
