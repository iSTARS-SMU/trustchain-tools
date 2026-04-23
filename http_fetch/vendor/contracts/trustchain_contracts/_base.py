"""
Base class for every contract DTO.

Every model in this package inherits ContractModel (never bare BaseModel).
Rationale: Pydantic v2 defaults to ``extra="ignore"`` — unknown fields are
silently dropped. For a wire contract that's disastrous: a typo'd field in
an engine's output would vanish with no error, and the engine author would
never know the dedup service didn't see their data.

``extra="forbid"`` turns unknown fields into validation errors.

Fields that MUST stay freeform (hints, payload, config, upstream_outputs,
secrets, SignatureEvidence.extra, …) remain typed as ``dict[str, Any]``.
`forbid` applies to the *containing model's* fixed schema, not to dict values,
so these continue to accept arbitrary keys.
"""

from pydantic import BaseModel, ConfigDict


class ContractModel(BaseModel):
    """Strict base. Rejects unknown fields on parse."""

    model_config = ConfigDict(extra="forbid")
