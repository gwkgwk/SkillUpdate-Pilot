"""Versioned HSDA facts, changes, evidence, and report models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Dimension = Literal["STRUCTURE", "SEMANTIC", "PERMISSION", "CODE_BEHAVIOR", "REFERENCE"]
Certainty = Literal["FACT", "UNKNOWN", "LLM_INFERENCE"]
ChangeType = Literal["ADDED", "REMOVED", "MODIFIED", "UNKNOWN"]


class SourceLocation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    snapshot: Literal["OLD", "NEW"]
    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    excerpt: str

    @model_validator(mode="after")
    def ordered_lines(self) -> SourceLocation:
        if self.end_line < self.start_line:
            raise ValueError("end_line must not precede start_line")
        return self


class SemanticFact(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str
    key: str
    value: str
    dimension: Dimension
    location: SourceLocation
    basis: Literal[
        "STATIC_MARKDOWN",
        "STATIC_PYTHON_AST",
        "STATIC_JAVASCRIPT_AST",
        "STATIC_YAML",
        "STATIC_JSON",
        "STATIC_REFERENCE",
        "STATIC_FILE_METADATA",
    ]
    certainty: Literal["FACT", "UNKNOWN"] = "FACT"
    security_relevant: bool = False
    risk_type: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class AnalyzerIssue(BaseModel):
    model_config = ConfigDict(extra="forbid")
    file: str
    analyzer: str
    code: str
    message: str
    certainty: Literal["UNKNOWN"] = "UNKNOWN"
    location: SourceLocation


class AnalyzerResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analyzer: str
    facts: list[SemanticFact] = Field(default_factory=list)
    issues: list[AnalyzerIssue] = Field(default_factory=list)


class SemanticChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    change_id: str
    dimension: Dimension
    change_type: ChangeType
    fact_kind: str
    key: str
    before_value: str | None = None
    after_value: str | None = None
    description: str
    analyzer: str
    certainty: Certainty
    evidence: list[SourceLocation] = Field(min_length=1)
    security_relevant: bool = False
    risk_type: str | None = None

    @model_validator(mode="after")
    def endpoints_match_change(self) -> SemanticChange:
        if self.change_type == "ADDED" and self.after_value is None:
            raise ValueError("ADDED changes require after_value")
        if self.change_type == "REMOVED" and self.before_value is None:
            raise ValueError("REMOVED changes require before_value")
        if self.change_type == "MODIFIED" and (
            self.before_value is None or self.after_value is None
        ):
            raise ValueError("MODIFIED changes require both values")
        return self


class SecurityEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evidence_id: str
    change_id: str
    risk_type: str
    assertion: str
    certainty: Certainty
    locations: list[SourceLocation] = Field(min_length=1)


class RawFileDiff(BaseModel):
    model_config = ConfigDict(extra="forbid")
    file: str
    change_type: Literal["ADDED", "REMOVED", "MODIFIED"]
    unified_diff: str
    sha256: str


class SnapshotSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    root: str
    sha256: str
    file_count: int = Field(ge=0)


class HSDAReport(BaseModel):
    """Complete P11 output; no field is an LLM conclusion."""

    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"] = "1.0"
    old_snapshot: SnapshotSummary
    new_snapshot: SnapshotSummary
    structure_changes: list[SemanticChange]
    semantic_changes: list[SemanticChange]
    permission_changes: list[SemanticChange]
    code_behavior_changes: list[SemanticChange]
    reference_changes: list[SemanticChange]
    security_evidence: list[SecurityEvidence]
    unknown_changes: list[SemanticChange]
    issues: list[AnalyzerIssue]
    raw_diffs: list[RawFileDiff]
    processing_time_ms: float = Field(ge=0)
    input_tokens: Literal[0] = 0
    output_tokens: Literal[0] = 0

    def as_json(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
