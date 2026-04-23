"""nuclei tool service — async wrapper around the `nuclei` binary.

Stateless. Core orchestrator forwards engine `ctx.call_tool('nuclei', {...})`
calls here AFTER scope-checking the target URL. This service runs
``nuclei -u <url> -jsonl -silent`` and returns the JSONL stdout.

Endpoints:
    GET  /healthz          liveness + nuclei version
    POST /invoke           NucleiRequest -> NucleiResult

Output:
    nuclei emits one JSON object per finding on stdout (`-jsonl` mode). We
    return the raw stdout — engines parse line-by-line. We don't pre-parse
    because the JSON shape varies by template type and would lock us in.

Security:
    The `target` field must be a well-formed http(s) URL (validated by
    ``_SAFE_URL_RE``). Argument injection is impossible because subprocess is
    invoked list-form AND the URL must start with ``http://`` or ``https://``,
    which prevents leading-dash flag smuggling.
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


# --- Target sanitation ----------------------------------------------------
# Must start with http:// or https://. Allowed chars after = RFC-3986-ish
# subset that covers any sensible target URL (host, port, path, query, frag).
# No spaces, no quotes, no shell metachars.
_SAFE_URL_RE = re.compile(
    r"^https?://[A-Za-z0-9._\-~:/\[\]?#@!$&'()*+,;=%]+$"
)


# --- Request / Result -----------------------------------------------------


class NucleiRequest(BaseModel):
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


class NucleiResult(BaseModel):
    target: str
    command: str
    returncode: int
    stdout: str
    """JSONL — one finding per line. Engines parse with ``json.loads`` per line."""
    stderr: str
    duration_ms: int
    success: bool


# --- Subprocess plumbing --------------------------------------------------


async def _run_nuclei(target: str, timeout_s: int) -> NucleiResult:
    cmd = ["nuclei", "-u", target, "-jsonl", "-silent"]
    logger.info("nuclei run target=%s timeout=%ss", target, timeout_s)
    started = asyncio.get_event_loop().time()

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        # Same convention as nmap: rc=127 in result, NOT a 500. Lets engines
        # tell "tool unhealthy" apart from "scan failed".
        return NucleiResult(
            target=target,
            command=" ".join(cmd),
            returncode=127,
            stdout="",
            stderr=f"nuclei binary not found: {exc}",
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
        return NucleiResult(
            target=target,
            command=" ".join(cmd),
            returncode=124,
            stdout="",
            stderr=f"timeout after {timeout_s}s",
            duration_ms=timeout_s * 1000,
            success=False,
        )

    rc = proc.returncode if proc.returncode is not None else -1
    return NucleiResult(
        target=target,
        command=" ".join(cmd),
        returncode=rc,
        stdout=stdout_b.decode("utf-8", errors="replace"),
        stderr=stderr_b.decode("utf-8", errors="replace"),
        duration_ms=int((asyncio.get_event_loop().time() - started) * 1000),
        success=(rc == 0),
    )


# --- App ------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    nuclei_path = shutil.which("nuclei")
    app.state.nuclei_path = nuclei_path
    if nuclei_path is None:
        logger.warning("nuclei binary not in PATH — /invoke will return 127")
    else:
        logger.info("nuclei available at %s", nuclei_path)
    yield


app = FastAPI(title="trustchain nuclei", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    nuclei_path = getattr(app.state, "nuclei_path", None) or shutil.which("nuclei")
    return {"status": "ok", "nuclei": nuclei_path or "missing"}


@app.post("/invoke", response_model=NucleiResult)
async def invoke(req: NucleiRequest) -> NucleiResult:
    return await _run_nuclei(req.target, req.timeout_s)
