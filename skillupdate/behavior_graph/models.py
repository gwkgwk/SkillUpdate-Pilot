"""Evidence-bound models for P12 incremental behavioral graphs."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

NodeKind = Literal[
    "Instruction", "File", "Function", "Tool", "Permission", "Data", "Endpoint"
]
Relation = Literal[
    "INSTRUCTS",
    "REFERENCES",
    "CALLS",
    "INVOKES",
    "READS",
    "WRITES",
    "CONNECTS_TO",
    "GRANTS",
]
EvidenceBasis = Literal[
    "STATIC_FACT", "RULE_INFERENCE", "LLM_INFERENCE", "DYNAMIC_OBSERVATION"
]


class GraphEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    snapshot: Literal["OLD", "NEW"]
    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    excerpt: str
    basis: EvidenceBasis
    producer: str

    @model_validator(mode="after")
    def valid_range(self) -> GraphEvidence:
        if self.end_line < self.start_line:
            raise ValueError("evidence line range is reversed")
        return self


class BehaviorNode(BaseModel):
    model_config = ConfigDict(extra="forbid")
    node_id: str
    kind: NodeKind
    semantic_key: str
    label: str
    owner_file: str
    basis: EvidenceBasis
    evidence: list[GraphEvidence] = Field(min_length=1)
    risk_tags: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)


class BehaviorEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")
    edge_id: str
    source_id: str
    target_id: str
    relation: Relation
    semantic_key: str
    owner_files: list[str] = Field(min_length=1)
    basis: EvidenceBasis
    evidence: list[GraphEvidence] = Field(min_length=1)
    risk_tags: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)


class BehaviorGraph(BaseModel):
    model_config = ConfigDict(extra="forbid")
    snapshot_id: str
    snapshot_sha256: str
    nodes: list[BehaviorNode]
    edges: list[BehaviorEdge]

    @model_validator(mode="after")
    def graph_integrity(self) -> BehaviorGraph:
        node_ids = {node.node_id for node in self.nodes}
        edge_ids = {edge.edge_id for edge in self.edges}
        if len(node_ids) != len(self.nodes):
            raise ValueError("node IDs must be unique")
        if len(edge_ids) != len(self.edges):
            raise ValueError("edge IDs must be unique")
        if any(
            edge.source_id not in node_ids or edge.target_id not in node_ids
            for edge in self.edges
        ):
            raise ValueError("edge endpoint does not exist")
        return self


class NodeAlignment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    old_node_id: str
    new_node_id: str
    method: Literal["EXACT_SEMANTIC_KEY", "FILE_CONTENT_RENAME", "FUNCTION_STRUCTURE"]
    confidence: float = Field(ge=0, le=1)
    evidence: list[GraphEvidence] = Field(min_length=1)


class EdgeAlignment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    old_edge_id: str
    new_edge_id: str
    method: Literal["ALIGNED_ENDPOINTS_AND_RELATION"]
    evidence: list[GraphEvidence] = Field(min_length=1)


class RiskPath(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path_id: str
    pattern: Literal[
        "SENSITIVE_DATA_TO_ENDPOINT",
        "PROCESS_TOOL_INVOCATION",
        "INSTRUCTION_TO_RISK_CAPABILITY",
        "PERMISSION_ENABLES_RISK_CAPABILITY",
    ]
    node_ids: list[str] = Field(min_length=2)
    edge_ids: list[str] = Field(min_length=1)
    risk_types: list[str] = Field(min_length=1)
    explanation: str
    evidence: list[GraphEvidence] = Field(min_length=1)
    basis: Literal["RULE_INFERENCE"] = "RULE_INFERENCE"
    added_component_ids: list[str] = Field(min_length=1)
    cross_file: bool


class IncrementalStats(BaseModel):
    model_config = ConfigDict(extra="forbid")
    changed_files: list[str]
    reused_files: list[str]
    recomputed_files: list[str]
    globally_rebuilt_relations: list[Relation]


class BehavioralGraphDelta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    old_graph: BehaviorGraph
    new_graph: BehaviorGraph
    node_alignments: list[NodeAlignment]
    edge_alignments: list[EdgeAlignment]
    added_nodes: list[BehaviorNode]
    removed_nodes: list[BehaviorNode]
    added_edges: list[BehaviorEdge]
    removed_edges: list[BehaviorEdge]
    new_risk_paths: list[RiskPath]
    incremental_stats: IncrementalStats
    processing_time_ms: float = Field(ge=0)
