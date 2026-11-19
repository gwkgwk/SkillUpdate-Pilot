"""Strongly typed P13 inputs, advisory outputs, and API audit records."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SnapshotStatus = Literal["BENIGN", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"]
UpdateImpact = Literal[
    "NO_NEW_RISK",
    "NEW_RISK",
    "RISK_INCREASED",
    "RISK_REDUCED",
    "RISK_REMOVED",
    "UNKNOWN",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvidenceCatalogItem(StrictModel):
    evidence_id: str
    snapshot: Literal["OLD", "NEW"]
    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    excerpt: str
    basis: Literal["STATIC_FACT", "RULE_INFERENCE", "UNKNOWN"]
    producer: str


class AnalysisPackage(StrictModel):
    """All model-visible content; every nested value is untrusted data."""

    schema_version: Literal["1.0"] = "1.0"
    update_id: str
    skill_metadata: dict[str, Any]
    old_function_summary: str
    new_function_summary: str
    structure_diff: list[dict[str, Any]]
    semantic_diff: list[dict[str, Any]]
    code_behavior_diff: list[dict[str, Any]]
    permission_diff: list[dict[str, Any]]
    reference_diff: list[dict[str, Any]]
    unknown_diff: list[dict[str, Any]]
    old_behavior_graph: dict[str, Any]
    new_behavior_graph: dict[str, Any]
    new_risk_paths: list[dict[str, Any]]
    evidence_catalog: list[EvidenceCatalogItem]
    analysis_issues: list[dict[str, Any]] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_evidence(self) -> AnalysisPackage:
        ids = [item.evidence_id for item in self.evidence_catalog]
        if len(ids) != len(set(ids)):
            raise ValueError("evidence catalog IDs must be unique")
        return self


class BehaviorStatement(StrictModel):
    behavior: str
    evidence_ids: list[str] = Field(min_length=1)


class EvidenceLocation(StrictModel):
    evidence_id: str
    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)


class SecurityAssessment(StrictModel):
    """Advisory model result. It is not the final Decision Engine result."""

    snapshot_status: SnapshotStatus
    update_impact: UpdateImpact
    risk_types: list[str]
    new_behaviors: list[BehaviorStatement]
    historical_behaviors: list[BehaviorStatement]
    evidence_files: list[str]
    evidence_locations: list[EvidenceLocation]
    attack_paths: list[str]
    reason: str
    confidence: float | None = Field(default=None, ge=0, le=1)
    verification_required: bool

    @model_validator(mode="after")
    def benign_has_no_current_risk_claim(self) -> SecurityAssessment:
        if self.snapshot_status == "BENIGN" and (
            self.risk_types or self.new_behaviors or self.attack_paths
        ):
            raise ValueError(
                "BENIGN cannot include current risk types, new risky behaviors, "
                "or attack paths"
            )
        return self


class TokenUsage(StrictModel):
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    estimated: bool = False


class ProviderResponse(StrictModel):
    text: str
    model: str
    usage: TokenUsage
    request_id: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class AnalyzerResult(StrictModel):
    update_id: str
    requested_model: str
    returned_model: str | None
    parse_status: Literal[
        "VALID", "INVALID_JSON", "INVALID_SCHEMA", "UNGROUNDED", "PROVIDER_ERROR"
    ]
    assessment: SecurityAssessment
    validation_errors: list[str]
    usage: TokenUsage
    latency_ms: float = Field(ge=0)
    attempts: int = Field(ge=0)
    audit_directory: str


def unknown_assessment(reason: str) -> SecurityAssessment:
    return SecurityAssessment(
        snapshot_status="UNKNOWN",
        update_impact="UNKNOWN",
        risk_types=[],
        new_behaviors=[],
        historical_behaviors=[],
        evidence_files=[],
        evidence_locations=[],
        attack_paths=[],
        reason=reason,
        confidence=None,
        verification_required=True,
    )
