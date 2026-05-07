"""dalfox tool service — async wrapper around the `dalfox` binary.

Stateless. Core orchestrator forwards engine `ctx.call_tool('dalfox', {...})`
calls here AFTER scope-checking the target URL. This service runs
``dalfox url <url> [-p <param>] [-X POST -d <data>] [-C <cookie>]
--format json --silence`` and returns the JSON stdout.

Endpoints:
    GET  /healthz          liveness + dalfox version
    POST /invoke           DalfoxRequest -> DalfoxResult

Output:
    dalfox emits JSON in `--format json` mode (one line per finding under
    `--silence`). We return raw stdout — engines parse with json.loads.
    Empty stdout = no XSS detected.

Security:
    - `target` must be a well-formed http(s) URL.
    - `param` / `cookie` / `data` strict regex; leading dash rejected.
    - `method` is an enum.
    - subprocess invoked list-form (no shell).
    - dalfox is read-only; safe at default settings.
"""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


_SAFE_URL_RE = re.compile(
    r"^https?://[A-Za-z0-9._\-~:/\[\]?#@!$&'()*+,;=%]+$"
)
_SAFE_PARAM_RE = re.compile(r"^[A-Za-z0-9_.\[\]~-]{1,128}$")
_SAFE_COOKIE_OR_DATA_RE = re.compile(r"^[A-Za-z0-9 _=&;,.+%/:\-]{1,4096}$")


class DalfoxRequest(BaseModel):
    model_config = {"extra": "forbid"}

    target: str = Field(..., min_length=8, max_length=2048)
    param: str | None = Field(
        default=None,
        description=(
            "Specific parameter name to test. If None, dalfox scans all "
            "GET/POST params it discovers."
        ),
    )
    method: Literal["GET", "POST"] = Field(default="GET")
    data: str | None = Field(
        default=None,
        description="POST body. Required when method=POST.",
    )
    cookie: str | None = Field(
        default=None,
        description="Cookie header value, e.g. 'PHPSESSID=abc; security=low'.",
    )
    timeout_s: int = Field(default=120, ge=10, le=900)

    @field_validator("target")
    @classmethod
    def _check_target(cls, v: str) -> str:
        if not _SAFE_URL_RE.match(v):
            raise ValueError(
                f"target {v!r} is not a well-formed http(s) URL "
                f"(or contains disallowed characters)"
            )
        return v

    @field_validator("param")
    @classmethod
    def _check_param(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if v.startswith("-") or not _SAFE_PARAM_RE.match(v):
            raise ValueError(
                f"param {v!r} contains disallowed characters or starts with '-'"
            )
        return v

    @field_validator("cookie", "data")
    @classmethod
    def _check_cookie_or_data(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if v.startswith("-") or not _SAFE_COOKIE_OR_DATA_RE.match(v):
            raise ValueError(
                "cookie/data contains disallowed characters or starts with '-'"
            )
        return v


class DalfoxResult(BaseModel):
    target: str
    command: str
    returncode: int
    stdout: str
    """JSON output. Empty = no XSS. Engines parse with json.loads per line."""
    stderr: str
    duration_ms: int
    success: bool


async def _run_dalfox(req: DalfoxRequest) -> DalfoxResult:
    cmd: list[str] = [
        "dalfox", "url", req.target,
        "--format", "json",
        "--silence",
    ]
    if req.param:
        cmd.extend(["-p", req.param])
    if req.cookie:
        cmd.extend(["-C", req.cookie])
    if req.method == "POST":
        if not req.data:
            return DalfoxResult(
                target=req.target,
                command=" ".join(cmd),
                returncode=2,
                stdout="",
                stderr="method=POST requires non-empty `data` body",
                duration_ms=0,
                success=False,
            )
        cmd.extend(["-X", "POST", "-d", req.data])

    logger.info(
        "dalfox run target=%s param=%s method=%s timeout=%ss",
        req.target, req.param, req.method, req.timeout_s,
    )
    started = asyncio.get_event_loop().time()

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        return DalfoxResult(
            target=req.target,
            command=" ".join(cmd),
            returncode=127,
            stdout="",
            stderr=f"dalfox binary not found: {exc}",
            duration_ms=int((asyncio.get_event_loop().time() - started) * 1000),
            success=False,
        )

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=req.timeout_s
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return DalfoxResult(
            target=req.target,
            command=" ".join(cmd),
            returncode=124,
            stdout="",
            stderr=f"timeout after {req.timeout_s}s",
            duration_ms=req.timeout_s * 1000,
            success=False,
        )

    rc = proc.returncode if proc.returncode is not None else -1
    return DalfoxResult(
        target=req.target,
        command=" ".join(cmd),
        returncode=rc,
        stdout=stdout_b.decode("utf-8", errors="replace"),
        stderr=stderr_b.decode("utf-8", errors="replace"),
        duration_ms=int((asyncio.get_event_loop().time() - started) * 1000),
        success=(rc == 0),
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    path = shutil.which("dalfox")
    app.state.dalfox_path = path
    if path is None:
        logger.warning("dalfox binary not in PATH — /invoke will return rc=127")
    else:
        logger.info("dalfox available at %s", path)
    yield


app = FastAPI(title="trustchain dalfox", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    path = getattr(app.state, "dalfox_path", None) or shutil.which("dalfox")
    return {"status": "ok", "dalfox": path or "missing"}


@app.post("/invoke", response_model=DalfoxResult)
async def invoke(req: DalfoxRequest) -> DalfoxResult:
    return await _run_dalfox(req)
