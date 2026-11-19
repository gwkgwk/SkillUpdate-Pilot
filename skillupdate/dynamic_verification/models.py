"""Risk-guided dynamic planning, differential trace, and observation schemas."""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from skillupdate.sandbox.models import (
    ContainerRunResult,
    EventCategory,
    ExecutionContext,
    MockEvent,
    SandboxPolicy,
)

RiskLevel = Literal["LOW", "MEDIUM", "HIGH"]
ObservationState = Literal["OBSERVED", "NOT_OBSERVED", "UNKNOWN"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class VerificationPlan(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    plan_id: str
    risk_level: RiskLevel
    depth: Literal["SKIP", "DIRECTED", "DEEP"]
    execution_required: bool
    selected_path_ids: list[str]
    selected_risk_types: list[str]
    selected_event_categories: list[EventCategory]
    old_fixture_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    new_fixture_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    context: ExecutionContext
    sandbox_policy: SandboxPolicy
    rationale: str

    @model_validator(mode="after")
    def level_matches_execution(self) -> VerificationPlan:
        if self.risk_level == "LOW" and (
            self.execution_required or self.depth != "SKIP"
        ):
            raise ValueError("LOW risk must skip dynamic execution")
        if self.risk_level != "LOW" and (
            not self.execution_required or not self.selected_event_categories
        ):
            raise ValueError("MEDIUM/HIGH plans require selected dynamic events")
        return self

    def digest(self) -> str:
        payload = json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(payload.encode()).hexdigest()


class ExecutionPermit(StrictModel):
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorization: Literal["P14_CONTROLLED_MOCK_ONLY"] = "P14_CONTROLLED_MOCK_ONLY"


class BehaviorDelta(StrictModel):
    category: EventCategory
    operation: str
    target: str
    old_count: int = Field(ge=0)
    new_count: int = Field(ge=0)
    change: Literal["ADDED", "REMOVED", "UNCHANGED"]
    old_event_ids: list[str]
    new_event_ids: list[str]


class DynamicObservation(StrictModel):
    category: EventCategory
    state: ObservationState
    delta_event_ids: list[str]
    explanation: str


class DynamicVerificationResult(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    plan_id: str
    risk_level: RiskLevel
    state: Literal["SKIPPED_LOW_RISK", "COMPLETED", "PARTIAL", "FAILED"]
    old_run: ContainerRunResult | None
    new_run: ContainerRunResult | None
    behavior_delta: list[BehaviorDelta]
    observations: list[DynamicObservation]
    evidence_events: list[MockEvent]
    limitations: list[str]
