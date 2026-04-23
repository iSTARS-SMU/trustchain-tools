"""nmap tool service — async subprocess wrapper around the `nmap` binary.

Stateless. Core orchestrator forwards engine `ctx.call_tool('nmap', {...})`
calls here AFTER scope-checking the target. This service then runs nmap and
returns structured stdout / stderr / returncode for each sub-scan.

Endpoints:
    GET  /healthz          liveness + nmap version
    POST /invoke           NmapRequest -> NmapResult

Scan modes (from LLMAppSec/services/security-tools/nmap, ported sync):
    basic          single run: `nmap -Pn -T4 -sV -sC <target>`
    comprehensive  three runs (full port + NSE + web-enum) merged
    web            web service enumeration only

Security:
    The `target` field is validated against ``_SAFE_TARGET_RE`` before being
    passed to subprocess. We use list-form ``create_subprocess_exec`` so shell
    injection is impossible, but argument injection (a target like
    ``-sS --script=http-shellshock``) IS possible if we don't gate the value.

    No outbound traffic happens here that core hasn't already scope-checked —
    but defense-in-depth: this tool refuses any target that fails the regex.
"""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


# --- Target sanitation ----------------------------------------------------
# Allowed: ASCII alnum, dot, hyphen, colon (IPv6 / port), slash (CIDR),
# square brackets (IPv6 literal). Hyphen MUST NOT lead — that would let a
# caller pass "-script-args=evil" as a "target".
_SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9\[]([A-Za-z0-9._:/\[\]\-]{0,253})$")

ScanMode = Literal["basic", "comprehensive", "web"]


# --- Request / Result -----------------------------------------------------


class NmapRequest(BaseModel):
    model_config = {"extra": "forbid"}

    target: str = Field(..., min_length=1, max_length=254)
    mode: ScanMode = "basic"
    timeout_s: int = Field(
        default=300,
        ge=10,
        le=1800,
        description="Hard limit on the nmap invocation. comprehensive mode runs 3 scans serially under this budget.",
    )

    @field_validator("target")
    @classmethod
    def _check_target(cls, v: str) -> str:
        if not _SAFE_TARGET_RE.match(v):
            raise ValueError(
                f"target {v!r} contains disallowed characters or starts with '-' "
                f"(possible argument injection)"
            )
        return v


class NmapScanRun(BaseModel):
    name: str
    command: str
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int


class NmapResult(BaseModel):
    target: str
    mode: ScanMode
    scans: list[NmapScanRun]
    """One entry for `basic` / `web`; three entries for `comprehensive`."""
    success: bool
    """True iff every sub-scan exited 0 within budget."""


# --- Subprocess plumbing --------------------------------------------------


async def _run_nmap(
    name: str, args: list[str], timeout_s: int
) -> NmapScanRun:
    """Run a single nmap invocation. Returns NmapScanRun (never raises for
    non-zero returncode — caller decides what 'failure' means)."""
    cmd = ["nmap", *args]
    logger.info("nmap run name=%s cmd=%s", name, " ".join(cmd))
    started = asyncio.get_event_loop().time()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        # nmap binary missing in image — return a structured failure rather
        # than a 500 so engines can distinguish "tool unhealthy" from
        # "scan failed".
        return NmapScanRun(
            name=name,
            command=" ".join(cmd),
            returncode=127,
            stdout="",
            stderr=f"nmap binary not found: {exc}",
            duration_ms=int((asyncio.get_event_loop().time() - started) * 1000),
        )

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=timeout_s
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return NmapScanRun(
            name=name,
            command=" ".join(cmd),
            returncode=124,  # GNU coreutils convention for timeout
            stdout="",
            stderr=f"timeout after {timeout_s}s",
            duration_ms=timeout_s * 1000,
        )

    return NmapScanRun(
        name=name,
        command=" ".join(cmd),
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=stdout_b.decode("utf-8", errors="replace"),
        stderr=stderr_b.decode("utf-8", errors="replace"),
        duration_ms=int((asyncio.get_event_loop().time() - started) * 1000),
    )


# --- Mode definitions -----------------------------------------------------


def _basic_args(target: str) -> list[tuple[str, list[str]]]:
    return [("basic", ["-Pn", "-T4", "-sV", "-sC", target])]


def _web_args(target: str) -> list[tuple[str, list[str]]]:
    return [
        (
            "web_enum",
            [
                "-p", "80,443,8080,8443",
                "-sV",
                "--script", "http-title,http-headers,http-server-header,http-methods",
                target,
            ],
        )
    ]


def _comprehensive_args(target: str) -> list[tuple[str, list[str]]]:
    return [
        ("full_port_scan", ["-p-", "-sV", "-O", "--open", "-T4", target]),
        ("nse_basic", ["-p-", "-sV", "--script", "default,safe", "-T4", target]),
        *_web_args(target),
    ]


_MODE_BUILDERS = {
    "basic": _basic_args,
    "comprehensive": _comprehensive_args,
    "web": _web_args,
}


# --- App ------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    nmap_path = shutil.which("nmap")
    app.state.nmap_path = nmap_path
    if nmap_path is None:
        logger.warning("nmap binary not in PATH — /invoke will return 127 per scan")
    else:
        logger.info("nmap available at %s", nmap_path)
    yield


app = FastAPI(title="trustchain nmap", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    # Defensive: tests using ASGITransport without lifespan won't have
    # nmap_path set on app.state. Fall back to a live `which` check.
    nmap_path = getattr(app.state, "nmap_path", None) or shutil.which("nmap")
    return {
        "status": "ok",
        "nmap": nmap_path or "missing",
    }


@app.post("/invoke", response_model=NmapResult)
async def invoke(req: NmapRequest) -> NmapResult:
    builder = _MODE_BUILDERS.get(req.mode)
    if builder is None:
        # ScanMode Literal already constrains this — guard for safety.
        raise HTTPException(status_code=400, detail=f"unknown mode {req.mode!r}")

    runs_spec = builder(req.target)

    # Comprehensive runs three scans serially under one shared budget; each
    # gets the remaining time so the whole call can't blow past req.timeout_s.
    deadline = asyncio.get_event_loop().time() + req.timeout_s
    scans: list[NmapScanRun] = []
    for name, args in runs_spec:
        remaining = max(1, int(deadline - asyncio.get_event_loop().time()))
        scans.append(await _run_nmap(name, args, remaining))

    success = all(s.returncode == 0 for s in scans)
    return NmapResult(target=req.target, mode=req.mode, scans=scans, success=success)
