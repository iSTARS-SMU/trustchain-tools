"""feroxbuster tool service — async wrapper around the `feroxbuster` binary.

Stateless. Engine collector forwards calls to ``POST /invoke`` AFTER scope-
checking the target URL. This service runs feroxbuster against a chosen
wordlist and returns the line-based stdout (one candidate URL per line).

API v0.2 — adds wordlist selection + budget / rate / depth controls so the
recon engine can drive content discovery without per-target tuning.

Endpoints:
    GET  /healthz          liveness + feroxbuster version + wordlist inventory
    POST /invoke           FeroxbusterRequest -> FeroxbusterResult

Output contract:
    `stdout` is line-based: one CANDIDATE URL per line. **No live status, no
    method.** The engine collector MUST post-verify each candidate via its
    own HTTP client (HEAD/GET) and only emit ReconSurfaces on
    HTTP 2xx/3xx/401/403 — see endpoint-discovery-spec § Phase A2 in the
    pentest-engine repo.

Security: same model as nuclei — `_SAFE_URL_RE` enforces a well-formed http(s)
URL, subprocess invoked list-form, no leading-dash flag smuggling possible.
The wordlist field is a Literal-restricted enum so callers cannot pass
arbitrary file paths.
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
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


# Wordlist registry — maps API enum values to file paths inside the image.
# `common` intentionally maps to None → use feroxbuster's compiled-in default
# so we don't ship a redundant copy. `ai-app` is the only baked file.
# `raft-large-words` is reserved for v0.3 (would require vendoring SecLists).
WordlistName = Literal["common", "ai-app"]

# Base dir is overridable for tests (point at repo's wordlists/ dir).
_WORDLIST_DIR = os.environ.get("FEROXBUSTER_WORDLIST_DIR", "/app/wordlists")
_WORDLIST_PATHS: dict[WordlistName, str | None] = {
    "common": None,  # feroxbuster default
    "ai-app": os.path.join(_WORDLIST_DIR, "ai-app.txt"),
}


class FeroxbusterRequest(BaseModel):
    model_config = {"extra": "forbid"}

    target: str = Field(..., min_length=8, max_length=2048)
    timeout_s: int = Field(
        default=300, ge=10, le=1800,
        description="Process wall-clock kill timer (server enforces). "
                    "Distinct from --time-limit which is feroxbuster's own "
                    "scan-duration cap.",
    )

    # API v0.2 fields — all optional, backward-compatible.
    rate_limit: int | None = Field(
        default=None, ge=1, le=10000,
        description="Outbound requests/second cap. Maps to "
                    "feroxbuster --rate-limit. Use to be polite on shared "
                    "infra and prevent WAF triggers.",
    )
    wordlist_name: WordlistName = Field(
        default="common",
        description="Which baked wordlist to use. `common` = feroxbuster "
                    "default (~4500 generic web paths); `ai-app` = curated "
                    "~200 AI/LLM/agent-app conventions. The engine should "
                    "pick `ai-app` when the target profile suggests an "
                    "AI / LLM / agent component.",
    )
    max_requests: int | None = Field(
        default=None, ge=1, le=1000000,
        description="Approximate request budget. feroxbuster has no native "
                    "request counter; when both `max_requests` and "
                    "`rate_limit` are provided, the service derives "
                    "`--time-limit = ceil(max_requests / rate_limit)` as "
                    "a soft cap. Otherwise this field is a hint the engine "
                    "collector enforces post-hoc by truncating the URL list.",
    )
    max_depth: int = Field(
        default=1, ge=1, le=10,
        description="Recursion depth. Default 1 (no recursion) to prevent "
                    "runaway scans on apps with deep nesting. Maps to "
                    "feroxbuster --depth.",
    )

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
    """One candidate URL per line. Engines MUST post-verify before emit."""
    stderr: str
    duration_ms: int
    success: bool
    # API v0.2 reflection — lets engine ledger record what budget/wordlist
    # this run actually used (the request shape may have defaults the
    # caller didn't set explicitly).
    wordlist_name: WordlistName
    rate_limit: int | None
    max_requests: int | None
    max_depth: int


def _build_command(
    target: str,
    *,
    wordlist_name: WordlistName,
    rate_limit: int | None,
    max_requests: int | None,
    max_depth: int,
) -> list[str]:
    """Translate the request into a feroxbuster argv list.

    Pure function — no side effects, no subprocess. Tested independently.
    """
    cmd = ["feroxbuster", "-u", target, "--no-state", "-q"]

    wordlist_path = _WORDLIST_PATHS[wordlist_name]
    if wordlist_path is not None:
        cmd += ["-w", wordlist_path]
    # When wordlist_path is None (`common`), feroxbuster uses its default.

    cmd += ["--depth", str(max_depth)]

    if rate_limit is not None:
        cmd += ["--rate-limit", str(rate_limit)]

    # max_requests → --time-limit derivation (only when rate_limit is known,
    # since feroxbuster has no native request-count cap). Otherwise the
    # field is documented as engine-side post-hoc.
    if max_requests is not None and rate_limit is not None:
        time_limit_s = max(1, math.ceil(max_requests / rate_limit))
        cmd += ["--time-limit", f"{time_limit_s}s"]

    return cmd


async def _run_feroxbuster(
    req: FeroxbusterRequest,
) -> FeroxbusterResult:
    cmd = _build_command(
        req.target,
        wordlist_name=req.wordlist_name,
        rate_limit=req.rate_limit,
        max_requests=req.max_requests,
        max_depth=req.max_depth,
    )
    logger.info(
        "feroxbuster run target=%s wordlist=%s rate=%s max_req=%s depth=%d timeout=%ds",
        req.target, req.wordlist_name, req.rate_limit, req.max_requests,
        req.max_depth, req.timeout_s,
    )
    started = asyncio.get_event_loop().time()

    common_reflection = {
        "wordlist_name": req.wordlist_name,
        "rate_limit": req.rate_limit,
        "max_requests": req.max_requests,
        "max_depth": req.max_depth,
    }

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        return FeroxbusterResult(
            target=req.target,
            command=" ".join(cmd),
            returncode=127,
            stdout="",
            stderr=f"feroxbuster binary not found: {exc}",
            duration_ms=int((asyncio.get_event_loop().time() - started) * 1000),
            success=False,
            **common_reflection,
        )

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=req.timeout_s
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return FeroxbusterResult(
            target=req.target,
            command=" ".join(cmd),
            returncode=124,
            stdout="",
            stderr=f"timeout after {req.timeout_s}s",
            duration_ms=req.timeout_s * 1000,
            success=False,
            **common_reflection,
        )

    rc = proc.returncode if proc.returncode is not None else -1
    return FeroxbusterResult(
        target=req.target,
        command=" ".join(cmd),
        returncode=rc,
        stdout=stdout_b.decode("utf-8", errors="replace"),
        stderr=stderr_b.decode("utf-8", errors="replace"),
        duration_ms=int((asyncio.get_event_loop().time() - started) * 1000),
        success=(rc == 0),
        **common_reflection,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    fx_path = shutil.which("feroxbuster")
    app.state.feroxbuster_path = fx_path
    if fx_path is None:
        logger.warning("feroxbuster binary not in PATH — /invoke will return 127")
    else:
        logger.info("feroxbuster available at %s", fx_path)

    # Pre-flight wordlist files (warn but don't crash — `common` doesn't
    # need a file, and devs running outside docker may not have ai-app
    # mounted at /app/wordlists).
    missing = []
    for name, path in _WORDLIST_PATHS.items():
        if path is not None and not os.path.isfile(path):
            missing.append(f"{name} ({path})")
    if missing:
        logger.warning("missing wordlists at startup: %s", ", ".join(missing))
    yield


app = FastAPI(title="trustchain feroxbuster", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, object]:
    fx_path = (
        getattr(app.state, "feroxbuster_path", None) or shutil.which("feroxbuster")
    )
    wordlists = {
        name: ("default" if path is None else
               ("present" if os.path.isfile(path) else f"missing:{path}"))
        for name, path in _WORDLIST_PATHS.items()
    }
    return {
        "status": "ok",
        "feroxbuster": fx_path or "missing",
        "api_version": "0.2",
        "wordlists": wordlists,
    }


@app.post("/invoke", response_model=FeroxbusterResult)
async def invoke(req: FeroxbusterRequest) -> FeroxbusterResult:
    return await _run_feroxbuster(req)
