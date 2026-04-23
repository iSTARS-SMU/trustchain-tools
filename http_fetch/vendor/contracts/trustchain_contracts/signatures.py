"""
Finding location_signature computation — SINGLE SOURCE OF TRUTH.

The dedup key is `(target_id, vuln_type, location_signature)`. If engines
hand-build signature strings they will inevitably disagree on format, and
cross-engine dedup collapses. This module is the only legal place to
produce a signature.

Usage (engine / SDK):

    from trustchain_contracts.signatures import (
        SignatureEvidence, compute_signature,
    )

    ev = SignatureEvidence(
        url="https://target/login?u=admin&p=x",
        method="POST",
        affected_parameters=["username"],
    )
    sig = compute_signature("sql_injection", ev)

Guarantees:
    * Deterministic — same (vuln_type, evidence) always returns same sig
    * Domain/port stripped — target_id already in dedup key, so signature
      captures "where inside the target", not "which alias"
    * Unknown vuln_type → deterministic default fallback (still stable)
"""

import hashlib
from typing import Any
from urllib.parse import parse_qsl, urlparse

from pydantic import Field

from ._base import ContractModel

# ============================================================
# Evidence DTO — what engines populate
# ============================================================


class SignatureEvidence(ContractModel):
    """Shared across all vuln_types; each type uses a subset.

    Fields that don't apply to a vuln_type are simply ignored by that type's
    signature function.
    """

    url: str
    method: str | None = None
    affected_parameter: str | None = None
    """Single-param vulnerabilities (reflected XSS, IDOR, ...)."""
    affected_parameters: list[str] = Field(default_factory=list)
    """Multi-param vulnerabilities (stored XSS, SQLi across several params, ...)."""
    extra: dict[str, Any] = Field(default_factory=dict)
    """Escape hatch for vuln_types that need additional discriminators. Use sparingly."""


# ============================================================
# Normalization helpers
# ============================================================


def _normalize_url_path(url: str) -> str:
    """Return a canonical "path?sortedQuery" form, host/port/scheme stripped.

    Intentional design:
        * Hostname stripped — target_id already distinguishes assets in the
          dedup key, and same bug across vhost aliases should collapse.
        * Path lowercased + trailing slash stripped (except root).
        * Query pairs sorted by key to stabilize order-insensitive dup.
        * Fragment dropped.
    """
    p = urlparse(url.strip())
    path = (p.path or "/").lower().rstrip("/") or "/"
    if not p.query:
        return path
    # Keep query keys only (values vary across samples and aren't location)
    pairs = sorted(k for k, _ in parse_qsl(p.query, keep_blank_values=True))
    return f"{path}?{','.join(pairs)}"


def _hash(parts: list[str]) -> str:
    """sha256 of parts joined with '|', truncated to 16 hex chars."""
    joined = "|".join(parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


# ============================================================
# Per-vuln_type signature functions
# ============================================================


def _sig_sql_injection(ev: SignatureEvidence) -> str:
    path = _normalize_url_path(ev.url)
    params = _params_list(ev)
    return _hash(["sqli", path, ",".join(params)])


def _sig_xss_reflected(ev: SignatureEvidence) -> str:
    path = _normalize_url_path(ev.url)
    param = ev.affected_parameter or ""
    return _hash(["xss_r", path, param])


def _sig_xss_stored(ev: SignatureEvidence) -> str:
    path = _normalize_url_path(ev.url)
    fields = sorted(ev.affected_parameters)
    return _hash(["xss_s", path, ",".join(fields)])


def _sig_csrf(ev: SignatureEvidence) -> str:
    path = _normalize_url_path(ev.url)
    method = (ev.method or "POST").upper()
    return _hash(["csrf", path, method])


def _sig_idor(ev: SignatureEvidence) -> str:
    # Use parameter *name*, not value — 1/2/3 shouldn't collapse into separate
    # findings, they're the same vulnerability class.
    path = _normalize_url_path(ev.url)
    param = ev.affected_parameter or ""
    return _hash(["idor", path, param])


def _sig_path_traversal(ev: SignatureEvidence) -> str:
    path = _normalize_url_path(ev.url)
    return _hash(["path_trav", path])


def _sig_rce(ev: SignatureEvidence) -> str:
    path = _normalize_url_path(ev.url)
    param = ev.affected_parameter or ""
    return _hash(["rce", path, param])


def _sig_default(ev: SignatureEvidence) -> str:
    """Fallback for unknown vuln_types. Deterministic so dedup still works;
    format is conservative so bad clustering is the worst case."""
    path = _normalize_url_path(ev.url)
    params = _params_list(ev)
    return _hash(["default", path, ",".join(params)])


def _params_list(ev: SignatureEvidence) -> list[str]:
    """Normalize single/multi param fields into one sorted list."""
    if ev.affected_parameters:
        return sorted(set(ev.affected_parameters))
    if ev.affected_parameter:
        return [ev.affected_parameter]
    return []


# ============================================================
# Dispatch table
# ============================================================


_DISPATCH = {
    "sql_injection": _sig_sql_injection,
    "xss_reflected": _sig_xss_reflected,
    "xss_stored": _sig_xss_stored,
    "csrf": _sig_csrf,
    "idor": _sig_idor,
    "path_traversal": _sig_path_traversal,
    "rce": _sig_rce,
    "command_injection": _sig_rce,  # identical signature shape
}


def compute_signature(vuln_type: str, evidence: SignatureEvidence) -> str:
    """Return the stable 16-char hex signature for a finding.

    Engine code SHOULD NOT call this directly — the SDK applies it when
    constructing a FindingCandidate. Direct callers: tests, dedup service.

    Unknown vuln_type falls back to a deterministic default; output is still
    stable across runs so dedup remains correct, just possibly less precise.
    """
    fn = _DISPATCH.get(vuln_type.lower(), _sig_default)
    return fn(evidence)


# Exposed for tests / external introspection
def known_vuln_types() -> list[str]:
    """List of vuln_types that have a dedicated signature function."""
    return sorted(_DISPATCH.keys())
