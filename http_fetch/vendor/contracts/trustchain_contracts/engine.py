"""
Engine HTTP contract DTOs — the central protocol between orchestrator and engine.

See doc/engine-contract.md for full narrative. This module defines:
    * EngineYamlSpec — the shape of every engine.yaml
    * RunContextEnvelope — POST /invoke request body (per-invoke, never cached)
    * EngineResult — POST /invoke response body
    * ErrorCode — standard error taxonomy, retryable-ness
    * supporting value objects (Capabilities, ResourceProfile, ...)
"""

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import Field

from ._base import ContractModel
from .domain import ArtifactKind, ArtifactRef, TargetRef
from .stages import FindingCandidate

# ============================================================
# engine.yaml — the registration manifest
# ============================================================


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Capabilities(ContractModel):
    """Engine self-declaration; drives UI gates and orchestrator policy
    (see spec §8.2 destructive gate).
    """

    destructive: bool = False
    """Engine may cause irreversible side-effects on target (exploit class).
    Orchestrator requires Target authorization_proof with destructive consent
    when destructive=true AND safe_mode=false."""
    network_egress: bool = True
    """Engine hits external endpoints (almost always true)."""
    uses_llm: bool = False
    """Engine invokes LLM. Envelope must include llm_config if true; else
    orchestrator returns LLM_CONFIG_MISSING."""
    writes_artifacts: bool = True
    """Engine may call ctx.save_artifact."""


class ResourceProfile(ContractModel):
    memory_mb: int = 512
    cpu: float = 0.5


class SecretRequirement(ContractModel):
    name: str
    """Symbolic name, e.g. "openai", "exa". Accessed as ctx.secrets.<name>."""
    required: bool = True


OnFailure = Literal["abort", "skip_to_report"]
"""0.1 policy for pipeline step failure handling. See spec §3.1.2."""


class EngineYamlSpec(ContractModel):
    """Authoritative shape of every `engine.yaml` file.

    Registry parses each yaml into this model. Engine's GET /schema endpoint
    returns a subset (see engine-contract §8) that must agree with the yaml.
    """

    # --- Identity ---
    id: str
    """Stable identifier, e.g. "targetinfo-agent". Combined with version for routing."""
    version: str
    """Semver. Changing version creates a distinct registry entry."""
    stage: str
    """One of the canonical active stages (see spec §3.2)."""
    entry: str
    """HTTP base URL of the engine service, e.g. "http://recon-targetinfo-svc:9600"."""
    source_repo: str | None = None
    """URL of the engine's source repo. Optional. Used by sync-external.sh."""
    image: str | None = None
    """Docker image tag in the shared registry. Required in production yaml."""

    # --- Capability / policy ---
    capabilities: Capabilities = Field(default_factory=Capabilities)
    risk_level: RiskLevel = RiskLevel.LOW
    timeout_default: int = 600
    """Seconds. Orchestrator sets deadline = now() + timeout_default; may be
    further tightened per Task config."""
    resource_profile: ResourceProfile = Field(default_factory=ResourceProfile)

    # --- Dependencies ---
    required_tools: list[str] = Field(default_factory=list)
    """Tool ids that must be healthy for this engine to be scheduled."""
    optional_tools: list[str] = Field(default_factory=list)
    secret_requirements: list[SecretRequirement] = Field(default_factory=list)
    artifact_types: list[ArtifactKind] = Field(default_factory=list)

    # --- I/O schemas ---
    input_schema: dict[str, Any] = Field(default_factory=dict)
    """JSON Schema or {"$ref": "trustchain-contracts://<path>"}."""
    output_schema: dict[str, Any] = Field(default_factory=dict)
    config_schema: dict[str, Any] = Field(default_factory=dict)
    """JSON Schema for user-facing Task config. Rendered by frontend as a form."""


# ============================================================
# RunContextEnvelope — POST /invoke request body
# ============================================================


class CallbackConfig(ContractModel):
    events_url: str
    tools_url: str
    token: str
    """Per-attempt callback token. Engine must include it as X-Callback-Token
    header on all callback requests. Orchestrator validates against the
    (stage_attempt_id, token) pair."""


class LLMConfig(ContractModel):
    """Task-level LLM configuration. See spec §3.1.1."""

    provider: str = "openai"
    default_model: str
    default_temperature: float = 0.2


class RunMetadata(ContractModel):
    initiated_by: str | None = None
    triggered_at: datetime | None = None


class RunContextEnvelope(ContractModel):
    """POST /invoke body. Constructed by orchestrator per-invocation;
    engine process MUST NOT cache any part of this between calls.
    See engine-contract §2.2.
    """

    # --- Identity ---
    run_id: str
    project_id: str
    stage: str
    stage_attempt_id: str
    """UUID. Unique per /invoke call. Tagged into every side effect
    (events, artifacts, tool calls)."""
    attempt_number: int = 1
    """1 on first invoke; +1 on each retry."""
    engine_id: str
    """Fully qualified, e.g. "targetinfo-agent@1.0.3"."""

    # --- Timing ---
    deadline: datetime

    # --- Inputs ---
    targets: list[TargetRef]
    upstream_outputs: dict[str, Any] = Field(default_factory=dict)
    """Key = stage name (e.g. "recon"), value = that stage's output DTO as dict.
    SDK parses per input_schema before handing to engine code."""
    config: dict[str, Any] = Field(default_factory=dict)
    """Task-level config_schema-valid payload."""

    # --- Auth / LLM (per-invoke, never cached) ---
    secrets: dict[str, str] = Field(default_factory=dict)
    """Raw secret values. SDK filters through engine.yaml's secret_requirements
    whitelist before exposing via ctx.secrets.<name>."""
    llm_config: LLMConfig | None = None
    """Must be present when engine.yaml capabilities.uses_llm=true, else
    orchestrator returns LLM_CONFIG_MISSING."""

    # --- Callback channel ---
    callbacks: CallbackConfig

    # --- Meta ---
    run_metadata: RunMetadata = Field(default_factory=RunMetadata)


# ============================================================
# Error taxonomy (defined before EngineResult so its fields can be typed)
# ============================================================


class ErrorCode(str, Enum):
    # 400 — caller fault, not retryable
    CONFIG_INVALID = "CONFIG_INVALID"
    CONTEXT_INVALID = "CONTEXT_INVALID"
    SECRET_MISSING = "SECRET_MISSING"
    LLM_CONFIG_MISSING = "LLM_CONFIG_MISSING"
    TARGET_NOT_FOUND = "TARGET_NOT_FOUND"

    # 403 — auth
    AUTHZ_FAILED = "AUTHZ_FAILED"
    SCOPE_VIOLATION = "SCOPE_VIOLATION"

    # 409 — attempt state conflict
    STAGE_SUPERSEDED = "STAGE_SUPERSEDED"

    # 5xx — transient / infra, retryable
    TARGET_UNREACHABLE = "TARGET_UNREACHABLE"
    TOOL_UNAVAILABLE = "TOOL_UNAVAILABLE"
    LLM_UNAVAILABLE = "LLM_UNAVAILABLE"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


#: Errors for which orchestrator may auto-retry (0.2). 0.1 always waits for
#: human retry-stage decision regardless.
RETRYABLE_ERRORS: frozenset[ErrorCode] = frozenset(
    {
        ErrorCode.TARGET_UNREACHABLE,
        ErrorCode.TOOL_UNAVAILABLE,
        ErrorCode.LLM_UNAVAILABLE,
        ErrorCode.DEADLINE_EXCEEDED,
        ErrorCode.INTERNAL_ERROR,
    }
)


# ============================================================
# EngineResult — POST /invoke response body
# ============================================================


class EngineStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


class FailedSubtask(ContractModel):
    name: str
    reason: str


class EngineMetrics(ContractModel):
    llm_tokens_input: int = 0
    llm_tokens_output: int = 0
    llm_cost_usd: float = 0.0
    tool_calls_total: int = 0
    duration_ms: int = 0


class EngineResult(ContractModel):
    """POST /invoke response.

    For status=success|partial, output / finding_candidates / artifact_refs
    carry the stage's authoritative results (see spec §7.2.1 — this is the
    ONLY source of truth for findings).

    For status=failed, error_code / error_message / retryable are set.
    """

    status: EngineStatus
    stage_attempt_id: str
    """Echoed so orchestrator can align with its in-flight state."""

    # --- Success / Partial ---
    output: dict[str, Any] | None = None
    """Shape governed by engine.yaml output_schema. None on failure."""
    finding_candidates: list[FindingCandidate] = Field(default_factory=list)
    """★ Authoritative finding source. Dedup service reads only these."""
    artifact_refs: list[ArtifactRef] = Field(default_factory=list)
    metrics: EngineMetrics = Field(default_factory=EngineMetrics)
    failed_subtasks: list[FailedSubtask] = Field(default_factory=list)
    """Populated when status=partial."""

    # --- Failed ---
    error_code: ErrorCode | None = None
    error_message: str | None = None
    retryable: bool | None = None
    partial_artifacts: list[ArtifactRef] = Field(default_factory=list)
    """Artifacts produced before failure; preserved for audit."""
