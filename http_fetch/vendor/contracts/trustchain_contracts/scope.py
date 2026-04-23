"""
Target authorization scope matcher — SHARED between SDK and core.

``authorized_scope`` is a list of patterns on each Target. Every outbound
request to the target host (via ``ctx.fetch`` / tool calls / etc.) must hit
one of these patterns. The MATCHING LOGIC lives here so SDK and core
evaluate identically — otherwise client-side and server-side checks could
disagree, which is how auth gets bypassed in practice.

Pattern formats (spec §8.1.1):
    * exact domain:         "target.example.com"
    * wildcard domain:      "*.target.example.com"
    * IPv4 literal:          "1.2.3.4"
    * IPv4 CIDR:             "1.2.3.0/24"
    * IPv6 literal / CIDR:   "2001:db8::1" / "2001:db8::/32"

Matching is case-insensitive for hostnames. Port is ignored.
"""

from __future__ import annotations

import ipaddress
from fnmatch import fnmatch
from typing import Iterable
from urllib.parse import urlparse


def url_in_scope(url: str, patterns: Iterable[str]) -> bool:
    """True if ``url``'s host matches any scope pattern.

    Empty URL or no patterns → False (fail closed). An IP literal URL matches
    IP/CIDR patterns; a domain URL matches exact/wildcard patterns. Protocol
    is not inspected — scope controls WHERE, not HOW.
    """
    if not url:
        return False
    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()
    return host_in_scope(host, patterns)


def host_in_scope(host: str, patterns: Iterable[str]) -> bool:
    """True if ``host`` matches any pattern. Fail-closed on empty host.

    Use this for tools whose target is a SINGLE host (e.g. http_fetch URL).
    For tools that accept a CIDR or host-spec (nmap), use ``target_in_scope``
    which additionally permits sub-CIDR / exact-CIDR targets.
    """
    if not host:
        return False
    # Strip IPv6 brackets — `urlparse` returns hostnames bracket-free but a
    # raw arg from a tool request may carry them.
    host_lc = host.lower().strip("[]")

    # Try to parse as IP once so each pattern check is cheap.
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    try:
        ip = ipaddress.ip_address(host_lc)
    except ValueError:
        ip = None

    for pattern in patterns:
        if _matches(host_lc, ip, pattern):
            return True
    return False


def target_in_scope(target: str, patterns: Iterable[str]) -> bool:
    """True if a scan ``target`` is authorized by ``patterns``.

    Broader than ``host_in_scope`` — also allows the target to be a CIDR
    (or single IP / hostname). Designed for tools like nmap where it is
    common to scan a network range:

        authorized_scope = ["10.0.0.0/24", "*.target.example"]
        target_in_scope("10.0.0.5",         scope)  → True (host in CIDR)
        target_in_scope("10.0.0.0/24",      scope)  → True (exact CIDR)
        target_in_scope("10.0.0.0/26",      scope)  → True (sub-CIDR of /24)
        target_in_scope("10.0.0.0/16",      scope)  → False (super-CIDR)
        target_in_scope("api.target.example", scope) → True (wildcard host)
        target_in_scope("evil.example",     scope)  → False

    Fail-closed on empty target / no patterns.
    """
    if not target:
        return False
    target_lc = target.lower().strip("[]")

    # CIDR target — needs sub-net containment check vs CIDR scope patterns.
    if "/" in target_lc:
        try:
            target_net = ipaddress.ip_network(target_lc, strict=False)
        except ValueError:
            return False
        for pattern in patterns:
            pat = pattern.strip()
            if "/" not in pat:
                continue
            try:
                pat_net = ipaddress.ip_network(pat, strict=False)
            except ValueError:
                continue
            if target_net.subnet_of(pat_net):
                return True
        return False

    # Single host / IP — defer to existing host_in_scope.
    return host_in_scope(target_lc, patterns)


# ============================================================
# Generic per-request scope gate (shared between core and DevHarness).
#
# Why this lives in contracts: core's /tools/{id}/invoke proxy AND
# DevHarness's local /tools/{id}/invoke fake both need to gate every
# tool request the same way, picking the right matcher per (tool_id,
# request payload). Re-implementing that dispatch in two places was
# the source of the Codex P2 finding (DevHarness used url_in_scope for
# nmap CIDR targets, missing super-CIDR rejection). Single function =
# zero drift.
# ============================================================


# Tools whose request payload's `target` field is a scan target — i.e.
# can legitimately be a CIDR / hostname / IP. Use ``target_in_scope``
# (CIDR-aware, rejects super-CIDR). Adding a new scan tool? Append to
# this set, not to per-tool ad-hoc gating.
SCAN_TARGET_TOOLS: frozenset[str] = frozenset({"nmap"})

# Request fields that can carry a scope-relevant value. First non-empty
# wins. New tools using a NON-standard field (e.g. "endpoint", "uri")
# silently bypass this gate — catch in code review when wiring the tool.
SCOPE_FIELDS: tuple[str, ...] = ("url", "target", "host")


class ScopeCheckResult:
    """Outcome of ``check_request_scope``.

    Three states:
      * ``passed = True``                          — no scope-relevant field, or matcher passed
      * ``passed = False``, ``field`` set          — a field tried to match but fell outside scope
      * (no field present at all)                  — passed=True, field=None, value=None

    The (field, value) tuple is for error reporting so callers can build
    a helpful "tool=X field=Y value=Z outside [...]" message.
    """

    __slots__ = ("passed", "field", "value", "matcher")

    def __init__(
        self,
        *,
        passed: bool,
        field: str | None = None,
        value: str | None = None,
        matcher: str | None = None,
    ) -> None:
        self.passed = passed
        self.field = field
        self.value = value
        self.matcher = matcher  # "url_in_scope" / "target_in_scope" / "host_in_scope"

    def __repr__(self) -> str:
        if self.passed:
            return f"ScopeCheckResult(passed=True, field={self.field!r})"
        return (
            f"ScopeCheckResult(passed=False, field={self.field!r}, "
            f"value={self.value!r}, matcher={self.matcher!r})"
        )


def check_request_scope(
    *,
    tool_id: str,
    request_payload: dict,
    authorized_scope: Iterable[str],
) -> ScopeCheckResult:
    """Generic per-request scope gate. Picks the right matcher based on
    tool identity and which scope-relevant field is present in the payload.

    Dispatch rules (must stay in sync between core's /invoke proxy and
    DevHarness's tool proxy — that's the whole point of putting this here):

    * scope-relevant value comes from the FIRST non-empty SCOPE_FIELDS field
    * tool in ``SCAN_TARGET_TOOLS`` → ``target_in_scope`` (CIDR-aware,
      rejects super-CIDR)
    * field == "url" OR value starts with http:// / https:// →
      ``url_in_scope`` (extracts hostname first)
    * otherwise → ``host_in_scope`` (bare host / IP literal)

    Returns ``ScopeCheckResult(passed=True)`` if no SCOPE_FIELDS field is
    present (caller's choice whether to allow that — core does, since
    not every tool has a URL/target/host).
    """
    scope_value: str | None = None
    scope_field: str | None = None
    for field in SCOPE_FIELDS:
        v = request_payload.get(field)
        if isinstance(v, str) and v:
            scope_value = v
            scope_field = field
            break

    if scope_value is None or scope_field is None:
        return ScopeCheckResult(passed=True, field=None, value=None)

    patterns = list(authorized_scope)

    if tool_id in SCAN_TARGET_TOOLS:
        ok = target_in_scope(scope_value, patterns)
        matcher = "target_in_scope"
    elif scope_field == "url" or scope_value.lower().startswith(("http://", "https://")):
        ok = url_in_scope(scope_value, patterns)
        matcher = "url_in_scope"
    else:
        ok = host_in_scope(scope_value, patterns)
        matcher = "host_in_scope"

    return ScopeCheckResult(
        passed=ok,
        field=scope_field,
        value=scope_value,
        matcher=matcher,
    )


def _matches(
    host: str,
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None,
    pattern: str,
) -> bool:
    pattern = pattern.strip()
    if not pattern:
        return False

    # CIDR?
    if "/" in pattern:
        try:
            net = ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            return False
        return ip is not None and ip in net

    # IP literal?
    try:
        pat_ip = ipaddress.ip_address(pattern)
        return ip is not None and ip == pat_ip
    except ValueError:
        pass

    # Domain exact or wildcard.
    return fnmatch(host, pattern.lower())
