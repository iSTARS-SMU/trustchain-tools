"""Tests for stage DTOs (stages.py) — focused on fields added/changed
rather than full coverage of the whole enum of shapes.

Phase 3.0.5b: Weakness DTO extension (`evidence_snippet` / `cvss_v3`).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from trustchain_contracts import Severity, Weakness


# ---------- Weakness: new fields default + accept values ----------


def test_weakness_minimal_no_new_fields():
    """Existing callers that don't set evidence_snippet / cvss_v3 still work."""
    w = Weakness(
        id="w_1",
        type="sql_injection",
        severity_hint=Severity.HIGH,
        description="Legacy caller shape",
        source="exa",
    )
    assert w.evidence_snippet is None
    assert w.cvss_v3 is None


def test_weakness_with_evidence_snippet():
    w = Weakness(
        id="w_1",
        type="cve",
        severity_hint=Severity.HIGH,
        description="CVE-2024-X — Django path traversal",
        source="nvd",
        cve="CVE-2024-X",
        evidence_snippet="80/tcp open http  nginx 1.18.0",
        cvss_v3=7.5,
    )
    assert w.evidence_snippet.startswith("80/tcp")
    assert w.cvss_v3 == 7.5


def test_weakness_round_trip_json_preserves_new_fields():
    """model_dump / model_validate should round-trip the new fields."""
    original = Weakness(
        id="w_2",
        type="xss",
        severity_hint=Severity.MEDIUM,
        description="reflected XSS",
        source="exa",
        evidence_snippet="<script>alert(1)</script>",
        cvss_v3=6.1,
    )
    roundtripped = Weakness.model_validate(original.model_dump(mode="json"))
    assert roundtripped == original


def test_weakness_accepts_cvss_v3_zero_and_ten():
    """CVSSv3 ranges 0.0 through 10.0 inclusive; no constraint on upper/lower
    at the DTO level (pydantic keeps it simple — business-rule checks live
    in the engine that populates the DTO)."""
    low = Weakness(
        id="w", type="x", severity_hint=Severity.LOW, description="d", source="nvd",
        cvss_v3=0.0,
    )
    high = Weakness(
        id="w", type="x", severity_hint=Severity.CRITICAL, description="d",
        source="nvd", cvss_v3=10.0,
    )
    assert low.cvss_v3 == 0.0
    assert high.cvss_v3 == 10.0


def test_weakness_source_stays_string_not_literal():
    """Weakness.source is deliberately loose (str, not Literal) to preserve
    backwards compat with "nuclei-template" / "manual" / etc. Non-canonical
    values pass; the canonical set is documented in the field docstring."""
    w = Weakness(
        id="w", type="x", severity_hint=Severity.LOW, description="d",
        source="some-future-source-we-havent-thought-of",
    )
    assert w.source == "some-future-source-we-havent-thought-of"
