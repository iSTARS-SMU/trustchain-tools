"""sqlmap tool service — async wrapper around the `sqlmap` Python CLI.

Stateless. Core orchestrator forwards engine `ctx.call_tool('sqlmap', {...})`
calls here AFTER scope-checking the target URL. This service runs
``sqlmap -u <url> -p <param> --batch --random-agent --level=N --risk=N
[--cookie=...] [--data=... --method=POST]`` and returns raw stdout.

Endpoints:
    GET  /healthz          liveness + sqlmap version
    POST /invoke           SqlmapRequest -> SqlmapResult

Output:
    sqlmap emits human-readable progress + a results block. We return raw
    stdout — engines (e.g. pentest-engine `sqli_sqlmap_wrapper`) parse for
    "is vulnerable" / "Type:" / "Payload:" / dbms detection. No pre-parse:
    sqlmap text format is stable across recent releases and over-parsing
    here would couple the service to one engine's needs.

Security:
    - `target` must be a well-formed http(s) URL (``_SAFE_URL_RE``).
    - `param` is restricted to RFC-3986 unreserved chars — no leading
      dash, no shell metacharacters → cannot inject sqlmap CLI flags.
    - `cookie` and `data` are restricted to printable ASCII without
      shell metacharacters; leading dash rejected.
    - `method` is an enum.
    - subprocess invoked list-form (no shell).
    - `--output-dir=/tmp/sqlmap-<pid>` keeps each invocation isolated;
      directory is best-effort cleaned after the call.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import tempfile
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


_SAFE_URL_RE = re.compile(
    r"^https?://[A-Za-z0-9._\-~:/\[\]?#@!$&'()*+,;=%]+$"
)
# HTTP parameter name — RFC-3986 unreserved + a couple realistic extras.
# Excludes leading dash (no flag smuggling) and any shell metacharacter.
_SAFE_PARAM_RE = re.compile(r"^[A-Za-z0-9_.\[\]~-]{1,128}$")
# Cookies / form bodies — printable ASCII minus shell metacharacters.
# Allows '=', '&', ';', ',', '+', '%', '/', '.', '_', '-', ' ', ':' which
# covers Set-Cookie + form-urlencoded payloads.
_SAFE_COOKIE_OR_DATA_RE = re.compile(r"^[A-Za-z0-9 _=&;,.+%/:\-]{1,4096}$")


class SqlmapRequest(BaseModel):
    model_config = {"extra": "forbid"}

    target: str = Field(..., min_length=8, max_length=2048)
    param: str | None = Field(
        default=None,
        description=(
            "Specific parameter name to test. If None, sqlmap auto-detects "
            "all GET/POST params. Engines should pass this when they have "
            "a payload_location to focus on (saves ~5x runtime)."
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
    level: int = Field(default=1, ge=1, le=5)
    risk: int = Field(default=1, ge=1, le=3)
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


class SqlmapResult(BaseModel):
    target: str
    command: str
    returncode: int
    stdout: str
    """sqlmap text output. Engines grep for 'is vulnerable' / 'Type:' / etc."""
    stderr: str
    duration_ms: int
    success: bool


async def _run_sqlmap(req: SqlmapRequest) -> SqlmapResult:
    output_dir = tempfile.mkdtemp(prefix="sqlmap-")
    cmd: list[str] = [
        "sqlmap",
        "-u", req.target,
        "--batch",
        "--random-agent",
        "--level", str(req.level),
        "--risk", str(req.risk),
        "--output-dir", output_dir,
        "--disable-coloring",
    ]
    if req.param:
        cmd.extend(["-p", req.param])
    if req.cookie:
        cmd.extend(["--cookie", req.cookie])
    if req.method == "POST":
        if not req.data:
            return SqlmapResult(
                target=req.target,
                command=" ".join(cmd),
                returncode=2,
                stdout="",
                stderr="method=POST requires non-empty `data` body",
                duration_ms=0,
                success=False,
            )
        cmd.extend(["--method", "POST", "--data", req.data])

    logger.info(
        "sqlmap run target=%s param=%s method=%s level=%d risk=%d timeout=%ss",
        req.target, req.param, req.method, req.level, req.risk, req.timeout_s,
    )
    started = asyncio.get_event_loop().time()

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        shutil.rmtree(output_dir, ignore_errors=True)
        return SqlmapResult(
            target=req.target,
            command=" ".join(cmd),
            returncode=127,
            stdout="",
            stderr=f"sqlmap binary not found: {exc}",
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
        shutil.rmtree(output_dir, ignore_errors=True)
        return SqlmapResult(
            target=req.target,
            command=" ".join(cmd),
            returncode=124,
            stdout="",
            stderr=f"timeout after {req.timeout_s}s",
            duration_ms=req.timeout_s * 1000,
            success=False,
        )

    shutil.rmtree(output_dir, ignore_errors=True)
    rc = proc.returncode if proc.returncode is not None else -1
    return SqlmapResult(
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
    path = shutil.which("sqlmap")
    app.state.sqlmap_path = path
    if path is None:
        logger.warning("sqlmap binary not in PATH — /invoke will return rc=127")
    else:
        logger.info("sqlmap available at %s", path)
    yield


app = FastAPI(title="trustchain sqlmap", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    path = getattr(app.state, "sqlmap_path", None) or shutil.which("sqlmap")
    return {"status": "ok", "sqlmap": path or "missing"}


@app.post("/invoke", response_model=SqlmapResult)
async def invoke(req: SqlmapRequest) -> SqlmapResult:
    return await _run_sqlmap(req)
