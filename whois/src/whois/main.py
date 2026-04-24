"""whois — HTTP wrapper over the system `whois` CLI.

Ported from LLMAppSec/services/security-tools/whois (73 LOC). Same
semantics; the only differences vs LLMAppSec:

- Synchronous /invoke (LLMAppSec used async task_id + /tasks polling).
  Matches the rest of trustchain/tools/ (nmap, dig, etc.).
- Lightly-parsed output: registrar / creation date / expiry / registrant
  org / name servers extracted from the raw whois text so engines don't
  need to re-parse. Raw stdout preserved too for operators that want it.

Used primarily by recon-targetinfo. Adds domain-registration signal
(age, registrar, expiration) that nmap/dig can't provide.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)


# ==============================================================
# Request / Response models
# ==============================================================


class WhoisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(
        description="Hostname or domain. whois tolerates IPs too but returns mostly empty results; hostname is the intended use.",
        min_length=1,
        max_length=256,
    )
    timeout_sec: float = Field(
        default=30.0,
        gt=0,
        le=120,
        description="Hard cap on the whois subprocess.",
    )


class WhoisResponse(BaseModel):
    success: bool
    target: str = ""
    registrar: str = ""
    creation_date: str = ""
    expiry_date: str = ""
    registrant_org: str = ""
    name_servers: list[str] = Field(default_factory=list)
    stdout: str = Field(default="", description="Raw whois stdout (trimmed to 16 KB).")
    returncode: int = 0
    duration_ms: int = 0
    error: str = ""


# ==============================================================
# Parsing
# ==============================================================


# whois fields are unformalized across TLDs — a pragmatic "try several key
# names" approach works better than regexing one canonical shape.
_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "registrar": ("Registrar:", "Sponsoring Registrar:", "registrar:"),
    "creation_date": ("Creation Date:", "Created On:", "Created:", "created:"),
    "expiry_date": (
        "Registry Expiry Date:",
        "Registrar Registration Expiration Date:",
        "Expiration Date:",
        "Expires:",
        "expires:",
    ),
    "registrant_org": (
        "Registrant Organization:",
        "Registrant Org:",
        "org:",
    ),
}


def _extract_first(stdout: str, keys: tuple[str, ...]) -> str:
    for line in stdout.splitlines():
        stripped = line.strip()
        for key in keys:
            if stripped.lower().startswith(key.lower()):
                return stripped[len(key):].strip()
    return ""


def _extract_name_servers(stdout: str) -> list[str]:
    # "Name Server:" is widely consistent.
    out: list[str] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        stripped = line.strip()
        if re.match(r"(?i)^name server:", stripped):
            val = stripped.split(":", 1)[1].strip().lower()
            if val and val not in seen:
                seen.add(val)
                out.append(val)
    return out


# ==============================================================
# FastAPI
# ==============================================================


app = FastAPI(
    title="trustchain-tool-whois",
    version="0.1.0",
    description="whois CLI wrapper. Returns parsed registration metadata + raw stdout.",
)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/schema")
async def schema() -> dict[str, Any]:
    return {
        "tool_id": "whois",
        "version": "0.1.0",
        "request_schema": WhoisRequest.model_json_schema(),
        "response_schema": WhoisResponse.model_json_schema(),
    }


@app.post("/invoke", response_model=WhoisResponse)
async def invoke(body: WhoisRequest) -> WhoisResponse:
    started = time.perf_counter()
    try:
        proc = await asyncio.create_subprocess_exec(
            "whois",
            body.target,
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
            return WhoisResponse(
                success=False,
                target=body.target,
                error="timeout",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
    except FileNotFoundError:
        return WhoisResponse(
            success=False,
            target=body.target,
            error="whois CLI not installed on tool image",
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    stdout = (stdout_b or b"").decode("utf-8", errors="replace")
    stderr = (stderr_b or b"").decode("utf-8", errors="replace")
    # Cap stored stdout at 16 KB — whois responses for domains with many
    # historical records occasionally go to 100 KB+; engines don't need
    # the detail.
    stdout_trimmed = stdout[:16_384]

    return WhoisResponse(
        success=proc.returncode == 0,
        target=body.target,
        registrar=_extract_first(stdout, _FIELD_ALIASES["registrar"]),
        creation_date=_extract_first(stdout, _FIELD_ALIASES["creation_date"]),
        expiry_date=_extract_first(stdout, _FIELD_ALIASES["expiry_date"]),
        registrant_org=_extract_first(stdout, _FIELD_ALIASES["registrant_org"]),
        name_servers=_extract_name_servers(stdout),
        stdout=stdout_trimmed,
        returncode=proc.returncode or 0,
        duration_ms=int((time.perf_counter() - started) * 1000),
        error=stderr[:500] if proc.returncode != 0 else "",
    )
