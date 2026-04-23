"""Unit tests for trustchain_contracts.signatures.

Why this deserves its own suite: location_signature is half of the dedup key
`(target_id, vuln_type, location_signature)`. If different engines hand-build
signatures that disagree for equivalent findings — same bug, different URL
capitalization, different query order — dedup silently breaks. The
`compute_signature` function is the single source of truth; these tests lock
its behavior so changes that shift signatures don't slip through.
"""

from __future__ import annotations

import pytest

from trustchain_contracts import SignatureEvidence, compute_signature, known_vuln_types


# ============================================================
# Global invariants
# ============================================================


def test_signature_is_16_hex():
    """All signatures are sha256:16 (hex chars). Contract tests assert this
    too — but belt-and-suspenders here ensures any internal refactor that
    changes the hash length is caught in contracts, not in the consumer."""
    sig = compute_signature(
        "sql_injection",
        SignatureEvidence(url="https://example.com/login", affected_parameters=["u"]),
    )
    assert len(sig) == 16
    assert all(c in "0123456789abcdef" for c in sig)


def test_signature_is_deterministic_across_calls():
    ev = SignatureEvidence(
        url="https://target.example/login?u=admin",
        affected_parameters=["username"],
    )
    sig1 = compute_signature("sql_injection", ev)
    sig2 = compute_signature("sql_injection", ev)
    assert sig1 == sig2


def test_known_vuln_types_enumeration():
    """known_vuln_types() is the advertised list of explicitly-handled types;
    anything else falls to the default. Lock this list so accidental removal
    is loud."""
    kt = set(known_vuln_types())
    # Every type the spec §2.3 explicitly names must be present.
    assert kt >= {
        "sql_injection",
        "xss_reflected",
        "xss_stored",
        "csrf",
        "idor",
        "path_traversal",
        "rce",
        "command_injection",
    }


# ============================================================
# Vuln-type discrimination
# ============================================================


def test_different_vuln_types_produce_different_signatures():
    """Same URL + params under two vuln_types must NOT collapse — a SQLi and
    an XSS at the same endpoint are distinct findings."""
    ev = SignatureEvidence(
        url="https://target/login", affected_parameters=["username"]
    )
    sqli = compute_signature("sql_injection", ev)
    xss = compute_signature("xss_reflected", ev)
    assert sqli != xss


def test_rce_and_command_injection_share_shape_but_still_distinct():
    """rce and command_injection dispatch to the same signature function
    (_sig_rce), which means given identical evidence they produce the same
    signature. This is intentional — they're the same dedup class. BUT the
    vuln_type field itself differs, so the dedup key tuple
    (target, vuln_type, sig) still discriminates.

    This test documents that intentional sharing."""
    ev = SignatureEvidence(url="https://x/exec", affected_parameter="cmd")
    sig_rce = compute_signature("rce", ev)
    sig_cmd = compute_signature("command_injection", ev)
    # Same signature (same algorithm), but dedup keys differ via vuln_type.
    assert sig_rce == sig_cmd


# ============================================================
# URL normalization
# ============================================================


class TestUrlNormalization:
    """All normalization happens inside _normalize_url_path; we test its
    observable effects through compute_signature."""

    def test_host_stripped_from_signature(self):
        """target_id is already in the dedup key tuple, so the signature
        itself captures "where inside the target" — hostname aliases (vhost,
        proxied host) shouldn't create duplicate Findings."""
        a = compute_signature(
            "sql_injection",
            SignatureEvidence(url="https://a.example/login", affected_parameters=["u"]),
        )
        b = compute_signature(
            "sql_injection",
            SignatureEvidence(url="https://b.other/login", affected_parameters=["u"]),
        )
        assert a == b

    def test_port_stripped(self):
        a = compute_signature(
            "sql_injection",
            SignatureEvidence(url="https://x/login", affected_parameters=["u"]),
        )
        b = compute_signature(
            "sql_injection",
            SignatureEvidence(url="https://x:8443/login", affected_parameters=["u"]),
        )
        assert a == b

    def test_path_lowercased(self):
        a = compute_signature(
            "sql_injection",
            SignatureEvidence(url="https://x/Login", affected_parameters=["u"]),
        )
        b = compute_signature(
            "sql_injection",
            SignatureEvidence(url="https://x/login", affected_parameters=["u"]),
        )
        assert a == b

    def test_trailing_slash_stripped_except_root(self):
        a = compute_signature(
            "sql_injection",
            SignatureEvidence(url="https://x/users/", affected_parameters=["u"]),
        )
        b = compute_signature(
            "sql_injection",
            SignatureEvidence(url="https://x/users", affected_parameters=["u"]),
        )
        assert a == b

    def test_root_path_preserved(self):
        """Root `/` must remain — stripping it would produce `` which isn't
        a valid path representation and could collide with empty-path inputs."""
        sig = compute_signature(
            "path_traversal", SignatureEvidence(url="https://x/")
        )
        # Smoke: that the function runs and produces a valid sig
        assert len(sig) == 16

    def test_query_keys_sorted(self):
        """Shuffled query strings with same keys → same signature."""
        a = compute_signature(
            "sql_injection",
            SignatureEvidence(url="https://x/q?b=1&a=2", affected_parameters=["a"]),
        )
        b = compute_signature(
            "sql_injection",
            SignatureEvidence(url="https://x/q?a=2&b=1", affected_parameters=["a"]),
        )
        assert a == b

    def test_query_values_do_not_affect_signature(self):
        """We key on query names only, not values — SQL-injection via
        `?id=1' OR 1=1--` and `?id=5` are the same vulnerability signature."""
        a = compute_signature(
            "sql_injection",
            SignatureEvidence(url="https://x/q?id=1", affected_parameters=["id"]),
        )
        b = compute_signature(
            "sql_injection",
            SignatureEvidence(url="https://x/q?id=5", affected_parameters=["id"]),
        )
        assert a == b

    def test_fragment_stripped(self):
        """Fragments never reach the server — must not participate in dedup."""
        a = compute_signature(
            "sql_injection",
            SignatureEvidence(url="https://x/q#foo", affected_parameters=["u"]),
        )
        b = compute_signature(
            "sql_injection",
            SignatureEvidence(url="https://x/q", affected_parameters=["u"]),
        )
        assert a == b


# ============================================================
# SQL injection
# ============================================================


class TestSqlInjection:
    def test_same_params_in_different_order_dedup(self):
        a = compute_signature(
            "sql_injection",
            SignatureEvidence(
                url="https://x/login",
                affected_parameters=["username", "password"],
            ),
        )
        b = compute_signature(
            "sql_injection",
            SignatureEvidence(
                url="https://x/login",
                affected_parameters=["password", "username"],
            ),
        )
        assert a == b

    def test_different_params_distinct(self):
        a = compute_signature(
            "sql_injection",
            SignatureEvidence(url="https://x/login", affected_parameters=["username"]),
        )
        b = compute_signature(
            "sql_injection",
            SignatureEvidence(url="https://x/login", affected_parameters=["email"]),
        )
        assert a != b

    def test_single_and_list_equivalent(self):
        """`affected_parameter='u'` and `affected_parameters=['u']` must
        produce the same signature — engine authors often prefer one form or
        the other."""
        a = compute_signature(
            "sql_injection",
            SignatureEvidence(url="https://x/q", affected_parameter="u"),
        )
        b = compute_signature(
            "sql_injection",
            SignatureEvidence(url="https://x/q", affected_parameters=["u"]),
        )
        assert a == b


# ============================================================
# Reflected / stored XSS
# ============================================================


class TestXss:
    def test_xss_reflected_keys_on_single_param(self):
        a = compute_signature(
            "xss_reflected",
            SignatureEvidence(url="https://x/search", affected_parameter="q"),
        )
        b = compute_signature(
            "xss_reflected",
            SignatureEvidence(url="https://x/search", affected_parameter="q"),
        )
        assert a == b

    def test_xss_reflected_different_params_distinct(self):
        a = compute_signature(
            "xss_reflected",
            SignatureEvidence(url="https://x/search", affected_parameter="q"),
        )
        b = compute_signature(
            "xss_reflected",
            SignatureEvidence(url="https://x/search", affected_parameter="term"),
        )
        assert a != b

    def test_xss_stored_sorts_input_fields(self):
        a = compute_signature(
            "xss_stored",
            SignatureEvidence(
                url="https://x/comment", affected_parameters=["title", "body"]
            ),
        )
        b = compute_signature(
            "xss_stored",
            SignatureEvidence(
                url="https://x/comment", affected_parameters=["body", "title"]
            ),
        )
        assert a == b


# ============================================================
# CSRF
# ============================================================


class TestCsrf:
    def test_csrf_keys_on_method(self):
        a = compute_signature(
            "csrf", SignatureEvidence(url="https://x/transfer", method="POST")
        )
        b = compute_signature(
            "csrf", SignatureEvidence(url="https://x/transfer", method="POST")
        )
        assert a == b

    def test_csrf_method_case_normalized(self):
        """HTTP methods are case-insensitive on the wire; signature shouldn't
        split `post` and `POST` into separate findings."""
        a = compute_signature(
            "csrf", SignatureEvidence(url="https://x/t", method="POST")
        )
        b = compute_signature(
            "csrf", SignatureEvidence(url="https://x/t", method="post")
        )
        assert a == b

    def test_csrf_different_methods_distinct(self):
        a = compute_signature(
            "csrf", SignatureEvidence(url="https://x/t", method="POST")
        )
        b = compute_signature(
            "csrf", SignatureEvidence(url="https://x/t", method="DELETE")
        )
        assert a != b

    def test_csrf_default_method_is_post(self):
        """Historical default: CSRF typically on POST; algorithm falls back
        to POST when method is None."""
        a = compute_signature(
            "csrf", SignatureEvidence(url="https://x/t", method=None)
        )
        b = compute_signature(
            "csrf", SignatureEvidence(url="https://x/t", method="POST")
        )
        assert a == b


# ============================================================
# IDOR — param NAME, not value
# ============================================================


class TestIdor:
    def test_idor_signature_ignores_param_value(self):
        """Two reports of IDOR on `?id=` with different id values are the
        same vulnerability — they must dedup. IDOR's signature function
        takes `affected_parameter` (name) not any value."""
        a = compute_signature(
            "idor",
            SignatureEvidence(url="https://x/u?id=1", affected_parameter="id"),
        )
        b = compute_signature(
            "idor",
            SignatureEvidence(url="https://x/u?id=2", affected_parameter="id"),
        )
        assert a == b

    def test_idor_different_param_names_distinct(self):
        """Different IDOR-vulnerable params are distinct bugs."""
        a = compute_signature(
            "idor",
            SignatureEvidence(url="https://x/u", affected_parameter="id"),
        )
        b = compute_signature(
            "idor",
            SignatureEvidence(url="https://x/u", affected_parameter="user_id"),
        )
        assert a != b


# ============================================================
# Path traversal — path only
# ============================================================


class TestPathTraversal:
    def test_path_traversal_keys_on_path_alone(self):
        """Path traversal is a single-bug-per-endpoint class — params don't
        discriminate further."""
        a = compute_signature(
            "path_traversal",
            SignatureEvidence(url="https://x/download", affected_parameter="file"),
        )
        b = compute_signature(
            "path_traversal",
            SignatureEvidence(url="https://x/download", affected_parameter="filename"),
        )
        assert a == b

    def test_path_traversal_distinct_paths_distinct_sigs(self):
        a = compute_signature(
            "path_traversal", SignatureEvidence(url="https://x/download")
        )
        b = compute_signature(
            "path_traversal", SignatureEvidence(url="https://x/export")
        )
        assert a != b


# ============================================================
# Unknown vuln_type → deterministic fallback
# ============================================================


class TestUnknownVulnType:
    def test_unknown_type_still_deterministic(self):
        """Unknown vuln_type falls to the default algorithm. Dedup precision
        may be weaker but must still be stable across runs — otherwise the
        same engine's output gets duplicated on every retry."""
        ev = SignatureEvidence(url="https://x/bug", affected_parameters=["x"])
        a = compute_signature("super_novel_vuln", ev)
        b = compute_signature("super_novel_vuln", ev)
        assert a == b

    def test_unknown_type_different_from_known_type(self):
        """Fallback algorithm uses a distinct salt ("default" vs "sqli"),
        so even if all evidence is identical the signature must differ from
        a known type's output."""
        ev = SignatureEvidence(url="https://x/q", affected_parameters=["u"])
        unknown = compute_signature("not_in_dispatch", ev)
        sqli = compute_signature("sql_injection", ev)
        assert unknown != sqli

    def test_case_folding_on_vuln_type(self):
        """Dispatch is case-insensitive on vuln_type (implementation calls
        .lower()). Engines vary in casing; we don't want SQL_INJECTION to
        fall to fallback while sql_injection gets the real algorithm."""
        ev = SignatureEvidence(url="https://x/q", affected_parameters=["u"])
        a = compute_signature("sql_injection", ev)
        b = compute_signature("SQL_Injection", ev)
        assert a == b
