"""
Tool invocation contracts.

Engines call external tools (nmap, nuclei, http_fetch, ...) ONLY via the
tools side channel exposed by the orchestrator. See engine-contract.md §4.

Generic envelope:
    POST {callbacks.tools_url}/{tool_id}/invoke  → ToolRequest
    ← ToolResponse

Each concrete tool defines its own request/result shape. `http_fetch` is
defined here because it's the built-in required by every engine that
touches a target. Scanner-specific shapes (NmapRequest, NucleiRequest, ...)
live alongside their tool source in `trustchain/tools/<name>/`.
"""

from typing import Any, Literal

from pydantic import Field

from ._base import ContractModel
from .domain import ArtifactRef

# ============================================================
# Generic envelope
# ============================================================


class ToolRequest(ContractModel):
    """POST body to `{callbacks.tools_url}/{tool_id}/invoke`."""

    run_id: str
    stage_attempt_id: str
    tool_id: str
    request: dict[str, Any]
    """Tool-specific payload; each tool validates its own shape."""
    timeout_s: float = 30.0


class ToolResponse(ContractModel):
    tool_id: str
    duration_ms: int
    result: dict[str, Any]
    """Tool-specific result payload."""


# ============================================================
# Built-in: http_fetch
#
# Engines access target sites through this tool. SDK wraps it as
# `ctx.fetch(url, ...)`. See engine-contract.md §4.5.
# ============================================================


HttpFetchMethod = Literal["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]


class HttpFetchRequest(ContractModel):
    url: str
    method: HttpFetchMethod = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    body: bytes | str | dict[str, Any] | None = None
    follow_redirects: bool = True
    max_response_bytes: int = 5 * 1024 * 1024
    """5 MB default. Bodies above this get truncated and the full payload
    is stored as an artifact; result returns body_artifact_ref instead."""


class HttpFetchResult(ContractModel):
    status_code: int
    headers: dict[str, str]
    body_preview: str = ""
    """First 4 KB of body, inline for quick engine reading."""
    body_artifact_ref: ArtifactRef | None = None
    """Set when the body exceeded inline size; full body in MinIO."""
    truncated: bool = False
    final_url: str
    """After redirect resolution (if follow_redirects=True)."""
