"""P16-B/C/D schemas for a version-aware Security Capability Flow Graph."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from skillupdate.capability.models import EvidenceRef

FlowKind = Literal[
    "DATA_FLOW", "NETWORK_FLOW", "PROCESS_FLOW", "TOOL_FLOW",
    "CONTROL_FLOW", "PRIVILEGE_FLOW", "INSTRUCTION_FLOW",
    "REFERENCE_FLOW", "UNKNOWN_FLOW",
]
Coverage = Literal["COMPLETE_FOR_GRAPH", "PARTIAL", "UNKNOWN"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SCFGNode(StrictModel):
    port_id: str
    semantic_key: str
    owner_node_id: str
    owner_semantic_key: str
    owner_file: str
    direction: Literal["SOURCE", "SINK", "TRANSFORM", "CONTROL"]
    data_type: str
    trust_zone: str
    capability_kinds: list[str] = Field(default_factory=list)
    risk_tags: list[str] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(min_length=1)


class SCFGEdge(StrictModel):
    edge_id: str
    semantic_key: str
    source_port_id: str | None
    target_port_id: str | None
    source_node_id: str
    target_node_id: str
    relation: str
    flow_kind: FlowKind
    basis: Literal["STATIC_FACT", "RULE_INFERENCE"]
    certainty: Literal["DIRECT_STATIC", "POSSIBLE", "UNRESOLVED"]
    source_trust_zone: str
    target_trust_zone: str
    crosses_trust_boundary: bool
    risk_tags: list[str] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(min_length=1)


class SCFGGraph(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    graph_id: str
    source_behavior_graph_id: str
    source_snapshot_sha256: str
    nodes: list[SCFGNode]
    edges: list[SCFGEdge]
    coverage: Coverage
    unresolved_edge_count: int = Field(ge=0)
    limitations: list[str] = Field(default_factory=list)


class SCFGPortAlignment(StrictModel):
    old_port_id: str
    new_port_id: str
    method: Literal["ALIGNED_OWNER_AND_PORT"]
    evidence: list[EvidenceRef] = Field(min_length=1)


class SCFGEdgeAlignment(StrictModel):
    old_edge_id: str
    new_edge_id: str
    method: Literal["ALIGNED_PORTS_AND_RELATION"]
    evidence: list[EvidenceRef] = Field(min_length=1)


class SCFGComponentChange(StrictModel):
    entity_type: Literal["PORT", "FLOW_EDGE"]
    change_type: Literal["ADDED", "REMOVED", "MODIFIED"]
    semantic_key: str
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    evidence: list[EvidenceRef] = Field(min_length=1)


class SCFGDelta(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    old_graph: SCFGGraph
    new_graph: SCFGGraph
    port_alignments: list[SCFGPortAlignment]
    edge_alignments: list[SCFGEdgeAlignment]
    added_nodes: list[SCFGNode]
    removed_nodes: list[SCFGNode]
    modified_nodes: list[SCFGComponentChange]
    added_edges: list[SCFGEdge]
    removed_edges: list[SCFGEdge]
    modified_edges: list[SCFGComponentChange]
    summary: dict[str, int]
    coverage: Coverage
    limitations: list[str] = Field(default_factory=list)


class SCFGRiskPath(StrictModel):
    path_id: str
    pattern: Literal[
        "SENSITIVE_DATA_TO_EXTERNAL",
        "PROCESS_EXECUTION",
        "INSTRUCTION_TO_RISK_CAPABILITY",
        "PRIVILEGE_TO_RISK_CAPABILITY",
    ]
    port_ids: list[str] = Field(min_length=2)
    owner_node_ids: list[str] = Field(min_length=1)
    edge_ids: list[str] = Field(min_length=1)
    risk_types: list[str] = Field(min_length=1)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    crosses_trust_boundary: bool
    is_new: bool
    introduced_component_ids: list[str] = Field(default_factory=list)
    explanation: str
    basis: Literal["RULE_INFERENCE"] = "RULE_INFERENCE"
    evidence: list[EvidenceRef] = Field(min_length=1)


class SCFGPathAnalysis(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    old_paths: list[SCFGRiskPath]
    new_paths: list[SCFGRiskPath]
    added_paths: list[SCFGRiskPath]
    removed_paths: list[SCFGRiskPath]
    persistent_paths: list[SCFGRiskPath]
    coverage: Coverage
    truncated: bool
    explored_states: int = Field(ge=0)
    limitations: list[str] = Field(default_factory=list)
