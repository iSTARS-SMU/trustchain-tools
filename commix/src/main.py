"""commix tool service — async wrapper around the `commix` Python CLI.

Stateless. Core orchestrator forwards engine `ctx.call_tool('commix', {...})`
calls here AFTER scope-checking the target URL. This service runs
``commix --url=<url> -p <param> --batch [--cookie ...] [--data ...]``
and returns raw stdout.

Endpoints:
    GET  /healthz          liveness + commix path
    POST /invoke           CommixRequest -> CommixResult

Output:
    commix emits human-readable progress + a verdict line. We return raw
    stdout — engines (e.g. pentest-engine `cmd_commix_wrapper`) parse for
    "is vulnerable to" / "OS:" / "technique" / payload extraction. No
    pre-parse so service stays decoupled from engine schema.

Security:
    - `target` must be a well-formed http(s) URL.
    - `param` / `cookie` / `data` strict regex; leading dash rejected.
    - `method` is an enum.
    - subprocess invoked list-form (no shell).
    - --batch mode runs `id` / `whoami` / `uname` only — read-only.
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


class CommixRequest(BaseModel):
    model_config = {"extra": "forbid"}

    target: str = Field(..., min_length=8, max_length=2048)
    param: str | None = Field(
        default=None,
        description=(
            "Specific parameter name to test. If None, commix auto-detects "
            "all GET/POST params."
        ),
    )
    method: Literal["GET", "POST"] = Field(default="GET")
    data: str | None = Field(
        default=None,
        description="POST body (form-urlencoded). Required when method=POST.",
    )
    cookie: str | None = Field(
        default=None,
        description="Cookie header value, e.g. 'PHPSESSID=abc; security=low'.",
    )
    level: int = Field(default=1, ge=1, le=3)
    timeout_s: int = Field(default=300, ge=30, le=1800)

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


class CommixResult(BaseModel):
    target: str
    command: str
    returncode: int
    stdout: str
    """commix text output. Engines grep 'is vulnerable to' / 'Technique:' / etc."""
    stderr: str
    duration_ms: int
    success: bool


async def _run_commix(req: CommixRequest) -> CommixResult:
    # --ignore-stdin: commix auto-detects non-TTY stdin (e.g. when invoked
    # via subprocess.PIPE) and switches to STDIN_PARSING mode, which
    # silently ignores --url. We always run as a subprocess, so opt out.
    cmd: list[str] = [
        "commix",
        "--url", req.target,
        "--batch",
        "--ignore-stdin",
        "--level", str(req.level),
    ]
    if req.param:
        cmd.extend(["-p", req.param])
    if req.cookie:
        cmd.extend(["--cookie", req.cookie])
    if req.method == "POST":
        if not req.data:
            return CommixResult(
                target=req.target,
                command=" ".join(cmd),
                returncode=2,
                stdout="",
                stderr="method=POST requires non-empty `data` body",
                duration_ms=0,
                success=False,
            )
        cmd.extend(["--data", req.data])

    logger.info(
        "commix run target=%s param=%s method=%s level=%d timeout=%ss",
        req.target, req.param, req.method, req.level, req.timeout_s,
    )
    started = asyncio.get_event_loop().time()

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        return CommixResult(
            target=req.target,
            command=" ".join(cmd),
            returncode=127,
            stdout="",
            stderr=f"commix binary not found: {exc}",
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
        return CommixResult(
            target=req.target,
            command=" ".join(cmd),
            returncode=124,
            stdout="",
            stderr=f"timeout after {req.timeout_s}s",
            duration_ms=req.timeout_s * 1000,
            success=False,
        )

    rc = proc.returncode if proc.returncode is not None else -1
    return CommixResult(
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
    path = shutil.which("commix")
    app.state.commix_path = path
    if path is None:
        logger.warning("commix binary not in PATH — /invoke will return rc=127")
    else:
        logger.info("commix available at %s", path)
    yield


app = FastAPI(title="trustchain commix", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    path = getattr(app.state, "commix_path", None) or shutil.which("commix")
    return {"status": "ok", "commix": path or "missing"}


@app.post("/invoke", response_model=CommixResult)
async def invoke(req: CommixRequest) -> CommixResult:
    return await _run_commix(req)
