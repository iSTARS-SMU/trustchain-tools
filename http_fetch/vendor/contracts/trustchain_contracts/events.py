"""
Event contracts for the SSE pipeline and persisted audit stream.

See spec §7 for design. Key invariants:
    - EventIn is what engines POST to orchestrator (no seq).
    - Event is the persisted / broadcast form (core fills seq + server_ts).
    - Engine-emittable kinds are a whitelist; SDK rejects others.
    - Per-kind payload shape is validated against the *Payload classes below.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import Field

from ._base import ContractModel

# ============================================================
# Enums
# ============================================================


class EventLevel(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARN = "warn"
    ERROR = "error"


class EventKind(str, Enum):
    # --- Orchestrator-only (lifecycle) ---
    RUN_STARTED = "run_started"
    RUN_COMPLETED = "run_completed"
    RUN_FAILED = "run_failed"
    RUN_CANCELLED = "run_cancelled"
    RUN_PAUSED = "run_paused"
    """Run reached the user-requested `until_stage` cleanly. Spec §3.6."""
    RUN_RESUMED = "run_resumed"
    """Operator triggered `POST /runs/{id}/resume`. Spec §3.6."""
    STAGE_STARTED = "stage_started"
    STAGE_COMPLETED = "stage_completed"
    STAGE_FAILED = "stage_failed"
    STAGE_SKIPPED = "stage_skipped"
    STAGE_SUPERSEDED = "stage_superseded"
    # Decision kinds reserved for 0.2 (human-gate). Emitted by orchestrator.
    DECISION_REQUESTED = "decision_requested"
    DECISION_RESOLVED = "decision_resolved"

    # --- Engine (work-observation) ---
    PROGRESS = "progress"
    LOG = "log"
    TOOL_INVOKED = "tool_invoked"
    LLM_CALL = "llm_call"
    FINDING_DISCOVERED = "finding_discovered"  # preview-only; see §7.2.1
    ARTIFACT_PRODUCED = "artifact_produced"


#: Whitelist of kinds the orchestrator ingestion accepts from engine containers.
#: Includes `tool_invoked` / `llm_call` because the SDK auto-emits them on behalf
#: of engine code (after actually invoking the tool / LLM). Defense-in-depth:
#: ingestion validates every incoming event against this set.
ENGINE_ALLOWED_KINDS: frozenset[EventKind] = frozenset(
    {
        EventKind.PROGRESS,
        EventKind.LOG,
        EventKind.TOOL_INVOKED,
        EventKind.LLM_CALL,
        EventKind.FINDING_DISCOVERED,
        EventKind.ARTIFACT_PRODUCED,
    }
)

#: Strict subset the SDK allows ENGINE CODE to emit directly via
#: `ctx.emit_event()`. Excludes `tool_invoked` / `llm_call` — those are
#: produced internally by SDK when a tool / LLM call actually happens, so
#: engine code cannot fake metrics by emitting them manually. SDK has a
#: separate internal emit path for these.
ENGINE_USER_EMITTABLE_KINDS: frozenset[EventKind] = frozenset(
    {
        EventKind.PROGRESS,
        EventKind.LOG,
        EventKind.FINDING_DISCOVERED,
        EventKind.ARTIFACT_PRODUCED,
    }
)


# ============================================================
# Event envelopes
# ============================================================


class EventIn(ContractModel):
    """What an engine POSTs to `{callbacks.events_url}`.

    No `seq` / `server_ts` — core assigns on ingestion. See spec §7.1.
    """

    client_ts: datetime
    run_id: str
    stage_attempt_id: str
    stage: str
    engine: str
    """Fully qualified engine id including version, e.g. "targetinfo-agent@1.0.3"."""
    kind: EventKind
    level: EventLevel = EventLevel.INFO
    payload: dict[str, Any] = Field(default_factory=dict)


class Event(EventIn):
    """Persisted / broadcast form. Adds the core-assigned fields."""

    seq: int
    """Per-run monotonic sequence, assigned at ingestion. Used for SSE replay."""
    server_ts: datetime


# ============================================================
# Per-kind payload shapes
#
# These are the preferred payload shapes per kind. Not enforced by the Event
# class itself (payload is `dict[str, Any]` for flexibility), but validated
# by core ingestion and the SDK emit helpers.
# ============================================================


class ProgressPayload(ContractModel):
    percentage: int = Field(ge=0, le=100)
    message: str | None = None


class LogPayload(ContractModel):
    message: str
    context: dict[str, Any] = Field(default_factory=dict)


class ToolInvokedPayload(ContractModel):
    tool_id: str
    duration_ms: int
    success: bool
    error_code: str | None = None


class LLMCallPayload(ContractModel):
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float = 0.0
    purpose: str | None = None
    prompt_excerpt: str = ""
    """First 200 chars of prompt. SDK tail-pads with sha256 of full prompt."""
    response_excerpt: str = ""


class FindingDiscoveredPayload(ContractModel):
    """Real-time UI preview. **Not authoritative** — see spec §7.2.1.
    The authoritative Finding path is EngineResult.finding_candidates → core dedup."""

    vuln_type: str
    severity: str
    preview: str
    """Short human-readable description for UI; not used for persistence."""


class ArtifactProducedPayload(ContractModel):
    artifact_id: str
    kind: str
    size_bytes: int
    sha256: str


# --- Orchestrator-owned payloads (engines can't emit these) ---


class StageStartedPayload(ContractModel):
    stage: str
    attempt_number: int
    engine: str


class StageCompletedPayload(ContractModel):
    stage: str
    attempt_number: int
    engine: str
    duration_ms: int


class StageFailedPayload(ContractModel):
    stage: str
    attempt_number: int
    engine: str
    error_code: str
    error_message: str
    retryable: bool


class StageSupersededPayload(ContractModel):
    stage: str
    superseded_attempt_number: int
    new_attempt_number: int
    reason: str
    """Why the old attempt was superseded: "retry_requested", "worker_crash", ..."""


class RunPausedPayload(ContractModel):
    """Run hit `until_stage` cleanly. Spec §3.6."""

    last_completed_stage: str
    next_stage: str | None
    """The stage that would run next on resume; `None` only when until_stage
    happens to be the final stage of the pipeline (rare but allowed)."""
    until_stage: str


class RunResumedPayload(ContractModel):
    """Operator called `POST /runs/{id}/resume`. Spec §3.6."""

    from_stage: str
    until_stage: str | None
