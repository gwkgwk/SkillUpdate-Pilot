"""P17 end-to-end pipeline result and conservative fusion decision schemas."""
from __future__ import annotations
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field
from skillupdate.decision.models import DecisionOutcome
from skillupdate.dynamic_verification.models import DynamicVerificationResult
from skillupdate.scfg.models import SCFGDelta, SCFGPathAnalysis
from skillupdate.capability.models import CapabilityDelta, CapabilitySnapshot
from skillupdate.behavior_graph.models import BehavioralGraphDelta
from skillupdate.hsda.models import HSDAReport
from skillupdate.llm.models import AnalyzerResult

class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

class PipelineDecision(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    update_id: str
    snapshot_status: Literal["BENIGN", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"]
    update_impact: Literal["NO_NEW_RISK", "NEW_RISK", "RISK_INCREASED", "RISK_REDUCED", "RISK_REMOVED", "UNKNOWN"]
    reason: str
    risk_types: list[str]
    new_scfg_path_ids: list[str]
    removed_scfg_path_ids: list[str]
    evidence: list[dict[str, Any]]
    verification_required: bool
    decision_basis: list[str]
    base_decision: DecisionOutcome
    dynamic_state: Literal["NOT_REQUESTED", "SKIPPED_LOW_RISK", "COMPLETED", "PARTIAL", "FAILED"]

class SkillUpdatePipelineResult(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    update_id: str
    hsda: HSDAReport
    behavior_graph: BehavioralGraphDelta
    old_capabilities: CapabilitySnapshot
    new_capabilities: CapabilitySnapshot
    capability_delta: CapabilityDelta
    scfg_delta: SCFGDelta
    scfg_paths: SCFGPathAnalysis
    llm_analysis: AnalyzerResult
    dynamic_verification: DynamicVerificationResult | None = None
    decision: PipelineDecision
    limitations: list[str] = Field(default_factory=list)
    processing_time_ms: float = Field(ge=0)
