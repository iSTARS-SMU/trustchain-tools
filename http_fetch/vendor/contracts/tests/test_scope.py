"""Unit tests for trustchain_contracts.scope — the shared auth matcher.

Why this module deserves dedicated tests: `url_in_scope` / `host_in_scope` run
on BOTH sides of the network — SDK pre-flight inside `ctx.fetch`, and core
inside the tool proxy. A behavioral drift between client and server is how
scope bypass actually happens in practice. So the tests here lock the matcher's
behavior at the function level, independent of either caller.
"""

from __future__ import annotations

import pytest

from trustchain_contracts.scope import host_in_scope, target_in_scope, url_in_scope


# ============================================================
# Fail-closed behavior
# ============================================================


def test_empty_url_fails_closed():
    """No URL → never in scope. Critical: don't default-open on bad input."""
    assert url_in_scope("", ["example.com"]) is False


def test_empty_patterns_fails_closed():
    """No patterns declared → nothing is in scope. Belt-and-suspenders for
    Targets created without authorized_scope populated."""
    assert url_in_scope("https://example.com/", []) is False


def test_empty_host_fails_closed():
    """Unparseable URL (no host) → fail closed, even with broad patterns."""
    assert url_in_scope("not-a-url", ["*"]) is False


def test_empty_patterns_iter_fails_closed():
    """Same, using generator form — host_in_scope accepts Iterable, not just list."""
    assert host_in_scope("example.com", iter([])) is False


# ============================================================
# Domain exact match
# ============================================================


def test_domain_exact_match():
    assert url_in_scope("https://example.com/", ["example.com"]) is True


def test_domain_exact_case_insensitive():
    """Host comparison must be case-insensitive — DNS is."""
    assert url_in_scope("https://EXAMPLE.com/path", ["example.com"]) is True
    assert url_in_scope("https://example.com/path", ["EXAMPLE.COM"]) is True


def test_domain_exact_does_not_match_subdomain():
    """`example.com` as a pattern does NOT cover `a.example.com` —
    explicit wildcard is required."""
    assert url_in_scope("https://sub.example.com/", ["example.com"]) is False


def test_domain_exact_does_not_match_sibling():
    assert url_in_scope("https://other.example.org/", ["example.com"]) is False


# ============================================================
# Domain wildcard
# ============================================================


def test_wildcard_matches_one_level_subdomain():
    assert url_in_scope("https://a.example.com/", ["*.example.com"]) is True


def test_wildcard_does_not_match_apex():
    """`*.example.com` means "some subdomain of example.com". The apex
    (example.com itself) is a distinct host — doesn't match."""
    assert url_in_scope("https://example.com/", ["*.example.com"]) is False


def test_wildcard_matches_multi_level_subdomain():
    """Current implementation uses fnmatch where '*' matches '.' too —
    so `*.example.com` also covers `a.b.example.com`. This test locks that
    behavior; if we later want to restrict to single-level, this test will
    break and force a conscious decision."""
    assert url_in_scope("https://a.b.example.com/", ["*.example.com"]) is True


def test_wildcard_case_insensitive():
    assert url_in_scope("https://SUB.Example.COM/", ["*.example.com"]) is True


# ============================================================
# IPv4 literal + CIDR
# ============================================================


def test_ipv4_literal_match():
    assert url_in_scope("http://1.2.3.4/", ["1.2.3.4"]) is True


def test_ipv4_literal_no_match():
    assert url_in_scope("http://1.2.3.5/", ["1.2.3.4"]) is False


def test_ipv4_cidr_match():
    assert url_in_scope("http://10.0.0.5/", ["10.0.0.0/24"]) is True


def test_ipv4_cidr_boundary():
    """`10.0.0.0/24` covers 10.0.0.0-10.0.0.255 but not 10.0.1.0."""
    assert url_in_scope("http://10.0.0.255/", ["10.0.0.0/24"]) is True
    assert url_in_scope("http://10.0.1.0/", ["10.0.0.0/24"]) is False


def test_ipv4_literal_does_not_match_domain_pattern():
    """An IP URL never matches a hostname pattern."""
    assert url_in_scope("http://1.2.3.4/", ["example.com"]) is False


def test_domain_does_not_match_ip_pattern():
    """Converse: a domain URL never matches an IP/CIDR pattern."""
    assert url_in_scope("http://example.com/", ["1.2.3.0/24"]) is False


# ============================================================
# IPv6 literal + CIDR
# ============================================================


def test_ipv6_literal_match():
    assert host_in_scope("2001:db8::1", ["2001:db8::1"]) is True


def test_ipv6_cidr_match():
    assert host_in_scope("2001:db8::abcd", ["2001:db8::/32"]) is True


def test_ipv6_cidr_no_match():
    assert host_in_scope("2001:dc8::1", ["2001:db8::/32"]) is False


# ============================================================
# Port / scheme / path are ignored
# ============================================================


def test_port_in_url_ignored():
    """authorized_scope doesn't encode ports — a pattern match must hold
    regardless of which port the request targets."""
    assert url_in_scope("https://example.com:8443/admin", ["example.com"]) is True


def test_scheme_ignored():
    """scope controls WHERE, not HOW — http/https/ftp all match the same
    host pattern."""
    assert url_in_scope("http://example.com/", ["example.com"]) is True
    assert url_in_scope("ftp://example.com/", ["example.com"]) is True


def test_path_and_query_ignored():
    assert url_in_scope("https://example.com/a/b?x=1#frag", ["example.com"]) is True


# ============================================================
# Multi-pattern: any-one-matches
# ============================================================


def test_multiple_patterns_any_match_passes():
    patterns = ["other.com", "*.example.com", "1.2.3.0/24"]
    assert url_in_scope("https://a.example.com/", patterns) is True
    assert url_in_scope("http://1.2.3.99/", patterns) is True
    assert url_in_scope("https://other.com/", patterns) is True


def test_multiple_patterns_all_miss_fails():
    patterns = ["other.com", "*.example.com", "1.2.3.0/24"]
    assert url_in_scope("https://evil.example.org/", patterns) is False


# ============================================================
# Malformed patterns: graceful handling
# ============================================================


def test_malformed_cidr_pattern_does_not_crash():
    """Invalid CIDR string must be silently ignored, not raise. One bad
    pattern in a Target shouldn't kill all scope checks for that Run."""
    assert url_in_scope("http://1.2.3.4/", ["not-a-cidr/99"]) is False


def test_empty_string_pattern_ignored():
    """Empty-string entry in the pattern list does not match anything."""
    assert url_in_scope("https://example.com/", ["", "example.com"]) is True
    assert url_in_scope("https://example.com/", [""]) is False


def test_whitespace_pattern_stripped():
    """Surrounding whitespace on a pattern shouldn't cause a silent miss —
    the matcher strips before parsing."""
    assert url_in_scope("https://example.com/", ["  example.com  "]) is True


# ============================================================
# Parametrized round-trip
# ============================================================


@pytest.mark.parametrize(
    "url,patterns,expected",
    [
        ("https://target.example/", ["target.example"], True),
        ("https://admin.target.example/", ["*.target.example"], True),
        ("https://target.example/", ["*.target.example"], False),  # wildcard excludes apex
        ("http://192.168.1.10/", ["192.168.0.0/16"], True),
        ("http://192.169.1.10/", ["192.168.0.0/16"], False),
        ("https://attacker.com/", ["target.example", "*.target.example"], False),
    ],
)
def test_roundtrip_matrix(url: str, patterns: list[str], expected: bool):
    assert url_in_scope(url, patterns) is expected


# ============================================================
# target_in_scope — CIDR-aware matcher for nmap-style scan targets
#
# host_in_scope rejects CIDR targets ("10.0.0.0/24") because it expects a
# single host. nmap legitimately accepts a CIDR as the scan target; gating
# nmap with target_in_scope lets engines scan an authorized network range
# without forcing per-host expansion.  (Codex P1.)
# ============================================================


def test_target_in_scope_single_host_in_cidr_pattern():
    assert target_in_scope("10.0.0.5", ["10.0.0.0/24"]) is True


def test_target_in_scope_exact_cidr_target():
    assert target_in_scope("10.0.0.0/24", ["10.0.0.0/24"]) is True


def test_target_in_scope_sub_cidr_target():
    """Engine scans a /26 inside an authorized /24 — allowed."""
    assert target_in_scope("10.0.0.0/26", ["10.0.0.0/24"]) is True


def test_target_in_scope_super_cidr_target_rejected():
    """Engine asks for a /16 when only a /24 is authorized — must reject."""
    assert target_in_scope("10.0.0.0/16", ["10.0.0.0/24"]) is False


def test_target_in_scope_cidr_target_against_host_pattern_rejected():
    """No CIDR pattern declared → CIDR target can't match a single-host pattern."""
    assert target_in_scope("10.0.0.0/24", ["10.0.0.5"]) is False


def test_target_in_scope_hostname_target_passes_through_to_host_in_scope():
    assert target_in_scope("api.target.example", ["*.target.example"]) is True
    assert target_in_scope("evil.example", ["*.target.example"]) is False


def test_target_in_scope_bracketed_ipv6():
    """Tools may receive a raw bracketed IPv6 ("[::1]") instead of the
    bracket-stripped form `urlparse` produces. Both must scope-check the
    same way."""
    assert target_in_scope("[::1]", ["::1"]) is True
    assert target_in_scope("::1", ["::1"]) is True


def test_target_in_scope_invalid_cidr_fails_closed():
    assert target_in_scope("not-a-cidr/24", ["10.0.0.0/24"]) is False


def test_target_in_scope_empty_target_fails_closed():
    assert target_in_scope("", ["10.0.0.0/24"]) is False


def test_host_in_scope_strips_brackets_too():
    """Same bracketed-IPv6 normalisation in host_in_scope so both matchers
    agree."""
    assert host_in_scope("[::1]", ["::1"]) is True


# ============================================================
# check_request_scope — generic per-request gate, shared by core's
# /tools/{id}/invoke proxy and DevHarness's local fake-core. Tests
# guarantee dispatch parity (Codex P2 — DevHarness used to silently
# accept super-CIDR for nmap because it bypassed target_in_scope).
# ============================================================

from trustchain_contracts.scope import check_request_scope  # noqa: E402


def test_check_request_scope_no_scope_field_passes():
    """No url/target/host in payload → gate doesn't fire (caller decides)."""
    r = check_request_scope(
        tool_id="exa-search",
        request_payload={"query": "cve django"},
        authorized_scope=["x.example"],
    )
    assert r.passed is True
    assert r.field is None
    assert r.value is None


def test_check_request_scope_nmap_super_cidr_rejected():
    """target_in_scope must reject /16 when scope is /24 — the bug Codex P2
    caught in DevHarness's pre-helper shortcut."""
    r = check_request_scope(
        tool_id="nmap",
        request_payload={"target": "10.0.0.0/16"},
        authorized_scope=["10.0.0.0/24"],
    )
    assert r.passed is False
    assert r.field == "target"
    assert r.value == "10.0.0.0/16"
    assert r.matcher == "target_in_scope"


def test_check_request_scope_nmap_sub_cidr_allowed():
    r = check_request_scope(
        tool_id="nmap",
        request_payload={"target": "10.0.0.0/26"},
        authorized_scope=["10.0.0.0/24"],
    )
    assert r.passed is True
    assert r.matcher == "target_in_scope"


def test_check_request_scope_nmap_exact_cidr_allowed():
    r = check_request_scope(
        tool_id="nmap",
        request_payload={"target": "10.0.0.0/24"},
        authorized_scope=["10.0.0.0/24"],
    )
    assert r.passed is True


def test_check_request_scope_nmap_host_in_cidr_allowed():
    r = check_request_scope(
        tool_id="nmap",
        request_payload={"target": "10.0.0.5"},
        authorized_scope=["10.0.0.0/24"],
    )
    assert r.passed is True


def test_check_request_scope_url_field_uses_url_matcher():
    """For non-scan tools, a `url` field gets parsed as a URL even when the
    value happens to look like a host."""
    r = check_request_scope(
        tool_id="http_fetch",
        request_payload={"url": "https://api.x.example/health"},
        authorized_scope=["api.x.example"],
    )
    assert r.passed is True
    assert r.matcher == "url_in_scope"


def test_check_request_scope_target_field_for_non_scan_tool_treats_as_host():
    """A non-scan tool with a `target` field that's a bare host (not URL)
    falls through host_in_scope, NOT target_in_scope (no CIDR semantics)."""
    r = check_request_scope(
        tool_id="dig",
        request_payload={"target": "api.x.example"},
        authorized_scope=["api.x.example"],
    )
    assert r.passed is True
    assert r.matcher == "host_in_scope"


def test_check_request_scope_value_starting_with_https_uses_url_matcher():
    """Even when the field is `target`, a value starting with https://
    triggers url_in_scope (extracts hostname for IP/wildcard matching)."""
    r = check_request_scope(
        tool_id="nuclei",
        request_payload={"target": "https://api.x.example/x"},
        authorized_scope=["api.x.example"],
    )
    assert r.passed is True
    assert r.matcher == "url_in_scope"


def test_check_request_scope_field_precedence_url_over_target():
    """SCOPE_FIELDS = (url, target, host) in that order — first non-empty wins."""
    r = check_request_scope(
        tool_id="some-tool",
        request_payload={
            "url": "https://allowed.example/x",
            "target": "evil.example",
        },
        authorized_scope=["allowed.example"],
    )
    assert r.passed is True
    assert r.field == "url"


def test_check_request_scope_ipv6_cidr_supernet_rejected():
    """Same super-CIDR rejection works for IPv6 (target_in_scope is
    IP-family-agnostic via subnet_of)."""
    r = check_request_scope(
        tool_id="nmap",
        request_payload={"target": "2001:db8::/32"},
        authorized_scope=["2001:db8::/48"],
    )
    assert r.passed is False
    assert r.matcher == "target_in_scope"


def test_check_request_scope_ipv6_cidr_subnet_allowed():
    r = check_request_scope(
        tool_id="nmap",
        request_payload={"target": "2001:db8::/56"},
        authorized_scope=["2001:db8::/48"],
    )
    assert r.passed is True
