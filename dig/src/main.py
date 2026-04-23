"""dig tool service — DNS record lookup via the `dig` binary.

Stateless. Called by core orchestrator on behalf of engines; recon-targetinfo
uses it for host info / LLM fingerprint input. Unlike LLMAppSec's dig-svc
(single `+short` A-record query), we query multiple record types in parallel
per request and return a structured map — a single recon call produces a
full DNS picture instead of engines looping per record type.

Endpoints:
    GET  /healthz         liveness + dig version
    POST /invoke          DigRequest → DigResult

Security:
    `target` is gated by ``_SAFE_DOMAIN_RE`` before subprocess. dig will
    happily shell-out to anything, so a target starting with `-` or
    containing quotes / backticks is refused at the model layer.
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


# RFC 1035-ish. Allows letters, digits, hyphens, dots. No leading hyphen —
# that would let `target` become a dig CLI flag (-q / etc). Empty → invalid.
_SAFE_DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._\-]{0,253})$")

RecordType = Literal["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV"]
_DEFAULT_RECORD_TYPES: list[RecordType] = ["A", "AAAA", "MX", "NS", "TXT"]


class DigRequest(BaseModel):
    model_config = {"extra": "forbid"}

    target: str = Field(..., min_length=1, max_length=254)
    record_types: list[RecordType] = Field(default_factory=lambda: list(_DEFAULT_RECORD_TYPES))
    timeout_s: int = Field(default=30, ge=5, le=300)

    @field_validator("target")
    @classmethod
    def _check_target(cls, v: str) -> str:
        v = v.strip().rstrip(".")  # trailing '.' is fine in DNS but we normalize
        if not _SAFE_DOMAIN_RE.match(v):
            raise ValueError(
                f"target {v!r} contains disallowed characters or starts with a hyphen"
            )
        return v


class DigRecord(BaseModel):
    record_type: str
    values: list[str]
    """dig +short output split by newlines; empty list if no records exist."""


class DigResult(BaseModel):
    target: str
    records: list[DigRecord]
    """One DigRecord per queried record_type, in request order."""
    duration_ms: int
    success: bool
    """True iff at least one record_type returned successfully (rc=0).
    A NXDOMAIN target still has success=true (dig exits 0 with empty stdout)."""


# --- Subprocess plumbing --------------------------------------------------


async def _dig_one(target: str, record_type: str, timeout_s: int) -> tuple[str, list[str], int]:
    """Run `dig +short <target> <record_type>`. Returns (rtype, values, rc).

    Values are stripped of trailing dots (typical DNS representation) and
    blank lines. Preserves order within a record type.
    """
    cmd = ["dig", "+short", target, record_type]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return (record_type, [], 127)

    try:
        stdout_b, _stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=timeout_s
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return (record_type, [], 124)

    rc = proc.returncode if proc.returncode is not None else -1
    stdout = stdout_b.decode("utf-8", errors="replace")
    values = [line.rstrip(".").strip() for line in stdout.splitlines() if line.strip()]
    return (record_type, values, rc)


# --- App ------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    dig_path = shutil.which("dig")
    app.state.dig_path = dig_path
    if dig_path is None:
        logger.warning("dig binary not in PATH — /invoke will return rc=127 per record")
    else:
        logger.info("dig available at %s", dig_path)
    yield


app = FastAPI(title="trustchain dig", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    dig_path = getattr(app.state, "dig_path", None) or shutil.which("dig")
    return {"status": "ok", "dig": dig_path or "missing"}


@app.post("/invoke", response_model=DigResult)
async def invoke(req: DigRequest) -> DigResult:
    started = asyncio.get_event_loop().time()
    # Parallel: each record type is an independent dig call. 5 types
    # concurrently = O(1) wall clock instead of O(n) serial.
    results = await asyncio.gather(
        *(_dig_one(req.target, rt, req.timeout_s) for rt in req.record_types),
        return_exceptions=False,
    )

    records = [
        DigRecord(record_type=rt, values=values)
        for (rt, values, _rc) in results
    ]
    success = any(rc == 0 for (_rt, _values, rc) in results)
    return DigResult(
        target=req.target,
        records=records,
        duration_ms=int((asyncio.get_event_loop().time() - started) * 1000),
        success=success,
    )
