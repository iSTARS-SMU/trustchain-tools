"""
Core domain DTOs — shared by API gateway, orchestrator, engines, frontend.

Kept minimal for 0.1-alpha; extend as services need more fields. Persisted ORM
models live inside `trustchain/core/*`, not here — this file is the wire format.
"""

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import Field

from ._base import ContractModel

# ============================================================
# Enums
# ============================================================


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    SUSPECTED = "suspected"


class FindingStatus(str, Enum):
    OPEN = "open"
    FIXED = "fixed"
    WONTFIX = "wontfix"
    FALSE_POSITIVE = "false_positive"


class VerificationState(str, Enum):
    UNVERIFIED = "unverified"
    EXPLOITED = "exploited"
    MANUALLY_CONFIRMED = "manually_confirmed"
    FIXED = "fixed"


class RunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


class StageAttemptStatus(str, Enum):
    RUNNING = "running"
    SUCCESSFUL = "successful"
    """Completed without error. Chosen over "completed" to avoid collision with
    the `stage_completed` event-kind string when reading code/logs."""
    FAILED = "failed"
    SKIPPED = "skipped"
    SUPERSEDED = "superseded"


class Role(str, Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


# 0.1 supports only these two. Mobile / llm-app targets are 0.2+.
TargetType = Literal["web", "api"]


ArtifactKind = Literal[
    "screenshot",
    "raw_output",
    "exploit_payload",
    "server_response",
    "log",
    "report",
]


# ============================================================
# References (lightweight DTOs used as fields of other models)
# ============================================================


class TargetRef(ContractModel):
    """Passed in RunContextEnvelope. Minimal subset of full Target."""

    id: str
    url: str
    resolved_ip: str | None = None
    target_type: TargetType = "web"
    authorized_scope: list[str] = Field(default_factory=list)
    """Patterns engine is allowed to hit. See spec §8.1.1.
    Formats: exact domain, `*.domain`, IPv4, IPv4/CIDR, IPv6, IPv6/CIDR.
    SDK enforces on ctx.fetch / ctx.call_tool."""


class ArtifactRef(ContractModel):
    """Reference to an artifact stored in MinIO."""

    id: str
    kind: ArtifactKind
    mime_type: str
    minio_key: str
    size_bytes: int
    sha256: str
    created_at: datetime
    run_id: str
    stage: str
    stage_attempt_id: str


class UserRef(ContractModel):
    id: str
    email: str
    role: Role = Role.OPERATOR


class ProjectRef(ContractModel):
    id: str
    name: str


class RunRef(ContractModel):
    id: str
    project_id: str
    status: RunStatus
    started_at: datetime | None = None


# ============================================================
# Finding (persisted, post-dedup)
#
# FindingCandidate (pre-dedup, engine output) lives in stages.py.
# Both carry the same vulnerability-description fields, but Finding
# adds lifecycle fields (status, first_seen, ...).
# ============================================================


class Finding(ContractModel):
    """Persisted Finding. See spec §2.2."""

    # --- Identity ---
    id: str
    project_id: str
    target_id: str

    # --- Vulnerability description (Required) ---
    vuln_type: str
    """Normalized string. See contracts enum (to grow): sql_injection, xss_reflected,
    xss_stored, csrf, idor, path_traversal, rce, command_injection, ..."""
    severity: Severity
    confidence: Confidence
    location_signature: str
    """Stable dedup key. Computed by trustchain_contracts.signatures.compute_signature;
    engine must NOT hand-build this."""
    evidence_artifact_refs: list[ArtifactRef] = Field(default_factory=list)

    # --- Lifecycle ---
    status: FindingStatus = FindingStatus.OPEN
    verification_state: VerificationState = VerificationState.UNVERIFIED
    first_seen_run_id: str
    last_seen_run_id: str

    # --- Optional enrichment (Should) ---
    cwe: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    owasp_category: str | None = None
    affected_endpoint: str | None = None
    affected_parameter: str | None = None
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)

    # --- Audit ---
    created_at: datetime
    updated_at: datetime
