"""P16-A typed capability inventory and evidence-backed update deltas."""
from __future__ import annotations
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field

CapabilityKind = Literal["FILE_READ","FILE_WRITE","NETWORK_CONNECT","DATA_ACCESS","DATA_TRANSFER","PROCESS_EXECUTION","TOOL_INVOCATION","PERMISSION_GRANT","INSTRUCTION","DEPENDENCY","UNKNOWN"]
PortDirection = Literal["SOURCE","SINK","TRANSFORM","CONTROL"]
BoundaryKind = Literal["TRUSTED_TO_UNTRUSTED","SENSITIVE_DATA","PRIVILEGE","EXTERNAL_ENDPOINT","UNKNOWN"]
ChangeKind = Literal["ADDED","REMOVED","MODIFIED"]

class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

class EvidenceRef(StrictModel):
    snapshot: Literal["OLD","NEW"]
    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    excerpt: str = ""
    basis: str
    producer: str = ""

class CapabilityPort(StrictModel):
    port_id: str
    owner_node_id: str
    owner_semantic_key: str
    direction: PortDirection
    data_type: str
    trust_zone: str = "UNCLASSIFIED"
    attributes: dict[str, Any] = Field(default_factory=dict)
    evidence: list[EvidenceRef] = Field(min_length=1)

class CapabilityEffect(StrictModel):
    effect_id: str
    source_port_id: str | None = None
    target_port_id: str | None = None
    source_node_id: str
    target_node_id: str
    relation: str
    effect_kind: str
    risk_tags: list[str] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(min_length=1)

class Capability(StrictModel):
    capability_id: str
    semantic_key: str
    kind: CapabilityKind
    label: str
    owner_node_id: str
    owner_file: str
    risk_tags: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)
    evidence: list[EvidenceRef] = Field(min_length=1)

class TrustBoundary(StrictModel):
    boundary_id: str
    boundary_kind: BoundaryKind
    node_id: str
    semantic_key: str
    trust_zone: str
    rationale: str
    evidence: list[EvidenceRef] = Field(min_length=1)

class CapabilitySnapshot(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    snapshot_id: str
    source_snapshot_sha256: str
    capabilities: list[Capability]
    ports: list[CapabilityPort]
    effects: list[CapabilityEffect]
    trust_boundaries: list[TrustBoundary]
    source_graph_node_count: int = Field(ge=0)
    source_graph_edge_count: int = Field(ge=0)
    coverage: Literal["COMPLETE_FOR_GRAPH","PARTIAL","UNKNOWN"]

    def digest(self) -> str:
        import hashlib, json
        payload = self.model_dump(mode="json")
        payload.pop("snapshot_id", None)
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

class CapabilityChange(StrictModel):
    change_id: str
    entity_type: Literal["CAPABILITY","PORT","EFFECT","TRUST_BOUNDARY"]
    change_type: ChangeKind
    semantic_key: str
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    evidence: list[EvidenceRef] = Field(min_length=1)

class CapabilityDelta(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    old_snapshot_id: str
    new_snapshot_id: str
    added: list[CapabilityChange]
    removed: list[CapabilityChange]
    modified: list[CapabilityChange]
    summary: dict[str, int]
    limitations: list[str] = Field(default_factory=list)
