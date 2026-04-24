"""
Stage I/O contracts.

Each canonical stage (see spec §3.2) has a standardized output DTO. Downstream
stage reads it from RunContextEnvelope.upstream_outputs[<stage>]. These DTOs
are the pipeline's lingua franca — different engines for the same stage MUST
produce structures that parse into the same DTO.
"""

from typing import Any, Literal

from pydantic import Field

from ._base import ContractModel
from .domain import ArtifactRef, Confidence, Finding, Severity, TargetRef
from .signatures import SignatureEvidence

HttpMethod = Literal["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]


# ============================================================
# recon → weakness_gather
# ============================================================


class TechFingerprint(ContractModel):
    framework: str | None = None
    server: str | None = None
    cms: str | None = None
    language: str | None = None
    versions: dict[str, str] = Field(default_factory=dict)


class Endpoint(ContractModel):
    path: str
    methods: list[HttpMethod]
    params: list[str] = Field(default_factory=list)
    auth_required: bool = False


class ReconOutput(ContractModel):
    target_ref: TargetRef
    tech_fingerprint: TechFingerprint
    endpoints: list[Endpoint] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)
    screenshots: list[ArtifactRef] = Field(default_factory=list)
    raw_tool_outputs: list[ArtifactRef] = Field(default_factory=list)
    notes: str | None = None


# ============================================================
# weakness_gather → attack_plan
# ============================================================


class Weakness(ContractModel):
    id: str
    """Unique within Run, e.g. "w_1"."""
    type: str
    """Normalized vuln type, e.g. "sql_injection". See stage §3.4 and signatures.py."""
    severity_hint: Severity
    description: str
    cve: str | None = None
    source: str
    """Provenance of this weakness. Canonical values:
        "nvd"             — authoritative NVD record (via nvd-search tool)
        "exa"             — extracted from exa-search web result
        "nuclei-template" — detected by a nuclei template match
        "manual"          — operator-added / hand-curated
        "llm"             — LLM-only inference (no external grounding; lowest confidence)
    Kept as ``str`` (not Literal) for backwards compat with legacy sources,
    but attack-plan and report engines should treat "nvd" > "nuclei-template" >
    "exa" > "llm" when ranking by confidence.
    """
    affected_endpoint: str | None = None
    references: list[str] = Field(default_factory=list)

    # --- Added 2026-04-24 (Phase 3.0.5b) for NVD/Exa dual-source weakness_gather ---
    evidence_snippet: str | None = None
    """Short quoted line from the upstream tool / source that justifies this
    weakness — e.g. the nmap stdout line ``80/tcp open http nginx 1.24.0``
    that triggered a CVE candidate, or the NVD description excerpt.
    Lets downstream stages (attack-plan, report) reason from raw evidence
    without re-loading upstream artifacts. Keep it short (~200 chars);
    large evidence belongs in artifact_refs."""

    cvss_v3: float | None = None
    """CVSSv3 base score (0.0–10.0). Set when provenance can authoritatively
    provide it — NVD records always can; Exa-derived entries only if a
    parseable NVD mirror was found. Used by attack-plan to rank candidates
    (see doc/TODO.md Phase 4 pre-rank logic). ``severity_hint`` is the
    engine's coarse classification; ``cvss_v3`` is the external score."""


class WeaknessGatherOutput(ContractModel):
    """Canonical output DTO for the ``weakness_gather`` stage (e.g. the
    weakness-gather-exa engine). Parallel to ``ReconOutput`` for recon.

    Wrapping plain ``list[Weakness]`` into this DTO gives downstream
    stages (attack_plan, report) access to provenance metadata — which
    tool sources were queried, whether any tool soft-failed — without
    having to infer from the weaknesses themselves. Added 2026-04-24
    (Phase 3.1) alongside the weakness-gather-exa engine.
    """

    target_ref: TargetRef
    """The target this weakness-gather pass was run against (pulled from
    upstream ReconOutput.target_ref)."""

    weaknesses: list[Weakness] = Field(default_factory=list)
    """Deduplicated, merged weakness candidates. Source ordering by the
    weakness-gather engine's dedup rule: NVD > nuclei-template > exa > llm
    (see Weakness.source field docstring)."""

    sources_queried: list[str] = Field(default_factory=list)
    """Which tool sources were actually queried AND returned at least
    one usable response. E.g. ``["nvd", "exa"]`` for a full dual-source
    run; ``["nvd"]`` alone if Exa was unavailable; ``[]`` if both were
    down (then ``notes`` explains and weaknesses is likely empty)."""

    notes: str | None = None
    """Human-readable summary of soft-failures + diagnostics. Surfaced
    in reports / audit trail. Typical contents: per-source availability,
    LLM extraction outcome, dedup stats."""


# ============================================================
# attack_plan → exploit
# ============================================================


class AttackStep(ContractModel):
    weakness_id: str
    objective: str
    target_url: str
    severity: Severity
    hints: dict[str, Any] = Field(default_factory=dict)
    """Free-form prompt hints the attack planner wants the exploit engine to see."""
    safe_mode: bool = True
    """Inherits Task-level safe_mode by default; may be tightened per step. Never relaxed here."""


class AttackPlan(ContractModel):
    steps: list[AttackStep]


# ============================================================
# exploit → verify (0.2) / report
# ============================================================


class ExploitResult(ContractModel):
    weakness_id: str
    success: bool
    commands: str = ""
    """Actual payload / script used, redacted of secrets. Keep short (≤1 KB); full
    artifact in evidence_refs."""
    server_response_summary: str = ""
    evidence_refs: list[ArtifactRef] = Field(default_factory=list)
    discovered_urls: list[str] = Field(default_factory=list)
    """URLs surfaced during exploitation that weren't in the original recon output.
    Used by verify stage (0.2) to trigger re-analysis."""


# ============================================================
# FindingCandidate — engine output (pre-dedup)
#
# Two-type split to separate engine-facing vs. wire concerns:
#
#   FindingCandidateDraft  — what engine CODE constructs (evidence, no signature)
#   FindingCandidate       — what goes over the wire (signature required)
#
# SDK's `ctx.emit_finding(draft)` / EngineResult assembly converts Draft
# into FindingCandidate by calling compute_signature on draft.signature_evidence.
# Engine code should NEVER construct FindingCandidate directly; R-lint will
# warn if it appears in non-SDK code.
# ============================================================


class _FindingFields(ContractModel):
    """Shared optional enrichment fields between Draft and wire DTO.
    Not exported; use FindingCandidate or FindingCandidateDraft directly."""

    cwe: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    owasp_category: str | None = None
    affected_endpoint: str | None = None
    affected_parameter: str | None = None
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)


class FindingCandidateDraft(_FindingFields):
    """What engine code constructs. SDK converts to FindingCandidate by
    computing signature from signature_evidence.

    ``target_id`` is optional in the Draft: SDK auto-fills it when the Run
    has exactly one target (unambiguous). Multi-target engines MUST set it
    explicitly — else SDK raises, since guessing which target a Finding
    belongs to would silently corrupt the dedup key ``(target_id, vuln_type,
    location_signature)``.

    Usage:
        await ctx.emit_finding(FindingCandidateDraft(
            vuln_type="sql_injection",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            signature_evidence=SignatureEvidence(
                url=req.url,
                affected_parameters=["username"],
            ),
            evidence_artifact_refs=[ref],
            affected_endpoint="/login",
            # target_id="t_456",   # required when ctx.targets has >1 entry
        ))
    """

    vuln_type: str
    severity: Severity
    confidence: Confidence
    signature_evidence: SignatureEvidence
    target_id: str | None = None
    evidence_artifact_refs: list[ArtifactRef] = Field(default_factory=list)


class FindingCandidate(_FindingFields):
    """Wire DTO. Goes into EngineResult.finding_candidates. Constructed ONLY
    by SDK (from a Draft); engine code must not instantiate directly.

    Invariants enforced at wire level:
        * ``target_id`` required — prevents orchestrator from picking a
          default and silently mis-attributing findings in multi-target runs.
        * ``signature_evidence`` required — core dedup recomputes
          ``compute_signature(vuln_type, signature_evidence)`` and rejects
          candidates where the recomputed sig doesn't match
          ``location_signature``. Defense against a broken / tampered SDK.
    """

    vuln_type: str
    severity: Severity
    confidence: Confidence
    target_id: str
    location_signature: str
    signature_evidence: SignatureEvidence
    evidence_artifact_refs: list[ArtifactRef] = Field(default_factory=list)


# ============================================================
# ReportInput — what core assembles and hands to report engine
# ============================================================


class ReportInput(ContractModel):
    run_id: str
    project_id: str
    target: TargetRef

    recon_output: ReconOutput | None = None
    weaknesses: list[Weakness] = Field(default_factory=list)
    attack_plan: AttackPlan | None = None
    exploit_results: list[ExploitResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    """Post-dedup persisted Findings (not Candidates)."""

    run_started_at: str | None = None
    run_completed_at: str | None = None
