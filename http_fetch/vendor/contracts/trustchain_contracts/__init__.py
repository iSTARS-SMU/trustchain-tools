"""
trustchain-contracts — shared data contracts for the TrustChain Pentest platform.

Import paths (stable):
    from trustchain_contracts import (
        TargetRef, ArtifactRef, Severity, Finding,        # domain
        ReconOutput, Weakness, AttackPlan, ExploitResult, # stages
        FindingCandidate, ReportInput,
        Event, EventKind, ENGINE_ALLOWED_KINDS,           # events
        ToolRequest, ToolResponse,                        # tools
        HttpFetchRequest, HttpFetchResult,
        EngineYamlSpec, RunContextEnvelope, EngineResult, # engine
        ErrorCode, RETRYABLE_ERRORS, Capabilities,
        SignatureEvidence, compute_signature,             # signatures
    )

See doc/spec.md and doc/engine-contract.md for narrative.
"""

from ._base import ContractModel
from .domain import (
    ArtifactKind,
    ArtifactRef,
    Confidence,
    Finding,
    FindingStatus,
    ProjectRef,
    Role,
    RunRef,
    RunStatus,
    Severity,
    StageAttemptStatus,
    TargetRef,
    TargetType,
    UserRef,
    VerificationState,
)
from .engine import (
    RETRYABLE_ERRORS,
    CallbackConfig,
    Capabilities,
    EngineMetrics,
    EngineResult,
    EngineStatus,
    EngineYamlSpec,
    ErrorCode,
    FailedSubtask,
    LLMConfig,
    OnFailure,
    ResourceProfile,
    RiskLevel,
    RunContextEnvelope,
    RunMetadata,
    SecretRequirement,
)
from .events import (
    ENGINE_ALLOWED_KINDS,
    ENGINE_USER_EMITTABLE_KINDS,
    ArtifactProducedPayload,
    Event,
    EventIn,
    EventKind,
    EventLevel,
    FindingDiscoveredPayload,
    LLMCallPayload,
    LogPayload,
    ProgressPayload,
    StageCompletedPayload,
    StageFailedPayload,
    StageStartedPayload,
    StageSupersededPayload,
    ToolInvokedPayload,
)
from .scope import (
    SCAN_TARGET_TOOLS,
    SCOPE_FIELDS,
    ScopeCheckResult,
    check_request_scope,
    host_in_scope,
    target_in_scope,
    url_in_scope,
)
from .signatures import (
    SignatureEvidence,
    compute_signature,
    known_vuln_types,
)
from .stages import (
    AttackPlan,
    AttackStep,
    Endpoint,
    ExploitResult,
    FindingCandidate,
    FindingCandidateDraft,
    HttpMethod,
    ReconOutput,
    ReportInput,
    TechFingerprint,
    Weakness,
    WeaknessGatherOutput,
)
from .tools import (
    HttpFetchMethod,
    HttpFetchRequest,
    HttpFetchResult,
    ToolRequest,
    ToolResponse,
)

__version__ = "0.1.0"

__all__ = [
    # base
    "ContractModel",
    # domain
    "ArtifactKind",
    "ArtifactRef",
    "Confidence",
    "Finding",
    "FindingStatus",
    "ProjectRef",
    "Role",
    "RunRef",
    "RunStatus",
    "Severity",
    "StageAttemptStatus",
    "TargetRef",
    "TargetType",
    "UserRef",
    "VerificationState",
    # stages
    "AttackPlan",
    "AttackStep",
    "Endpoint",
    "ExploitResult",
    "FindingCandidate",
    "FindingCandidateDraft",
    "HttpMethod",
    "ReconOutput",
    "ReportInput",
    "TechFingerprint",
    "Weakness",
    "WeaknessGatherOutput",
    # events
    "ArtifactProducedPayload",
    "ENGINE_ALLOWED_KINDS",
    "ENGINE_USER_EMITTABLE_KINDS",
    "Event",
    "EventIn",
    "EventKind",
    "EventLevel",
    "FindingDiscoveredPayload",
    "LLMCallPayload",
    "LogPayload",
    "ProgressPayload",
    "StageCompletedPayload",
    "StageFailedPayload",
    "StageStartedPayload",
    "StageSupersededPayload",
    "ToolInvokedPayload",
    # tools
    "HttpFetchMethod",
    "HttpFetchRequest",
    "HttpFetchResult",
    "ToolRequest",
    "ToolResponse",
    # engine
    "RETRYABLE_ERRORS",
    "CallbackConfig",
    "Capabilities",
    "EngineMetrics",
    "EngineResult",
    "EngineStatus",
    "EngineYamlSpec",
    "ErrorCode",
    "FailedSubtask",
    "LLMConfig",
    "OnFailure",
    "ResourceProfile",
    "RiskLevel",
    "RunContextEnvelope",
    "RunMetadata",
    "SecretRequirement",
    # scope
    "SCAN_TARGET_TOOLS",
    "SCOPE_FIELDS",
    "ScopeCheckResult",
    "check_request_scope",
    "host_in_scope",
    "target_in_scope",
    "url_in_scope",
    # signatures
    "SignatureEvidence",
    "compute_signature",
    "known_vuln_types",
    # version
    "__version__",
]
