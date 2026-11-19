"""Final P13 decision schema, separate from the advisory model response."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from skillupdate.llm.models import (
    BehaviorStatement,
    EvidenceLocation,
    SnapshotStatus,
    StrictModel,
    UpdateImpact,
)


class DecisionOutcome(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    policy_version: Literal["skillupdate-decision-v1"] = "skillupdate-decision-v1"
    update_id: str
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
    llm_advisory_status: SnapshotStatus
    decision_basis: list[
        Literal[
            "HSDA_STATIC_FACT",
            "BEHAVIOR_GRAPH_RULE",
            "LLM_ADVISORY",
            "COVERAGE_LIMITATION",
        ]
    ]
