"""Build port-level SCFG edges from P12 relations and P16-A capabilities."""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Iterable

from skillupdate.behavior_graph.models import BehaviorGraph, BehaviorNode
from skillupdate.capability.models import CapabilitySnapshot, EvidenceRef

from .models import SCFGEdge, SCFGGraph, SCFGNode


def _stable_id(prefix: str, value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:20]}"


def _unique_evidence(items: Iterable[EvidenceRef]) -> list[EvidenceRef]:
    values = {
        item.model_dump_json(): item
        for item in items
    }
    return [values[key] for key in sorted(values)]


class SCFGBuilder:
    """Create a static, evidence-backed capability-flow graph.

    READS is oriented from the data source to the reading function; WRITES is
    oriented from the writing function to the destination. A function-scope
    input-to-output edge is emitted only when the same function has both a
    read and an output operation, and is explicitly marked POSSIBLE.
    """

    @staticmethod
    def _select_port(ports: list, directions: tuple[str, ...]):
        for direction in directions:
            for port in ports:
                if port.direction == direction:
                    return port
        return ports[0] if ports else None

    def build(
        self, graph: BehaviorGraph, capabilities: CapabilitySnapshot
    ) -> SCFGGraph:
        if graph.snapshot_sha256 != capabilities.source_snapshot_sha256:
            raise ValueError("capability snapshot does not belong to this behavior graph")
        behavior_nodes = {node.node_id: node for node in graph.nodes}
        ports_by_owner: dict[str, list] = defaultdict(list)
        for port in capabilities.ports:
            ports_by_owner[port.owner_node_id].append(port)
        capabilities_by_owner: dict[str, list[str]] = defaultdict(list)
        for capability in capabilities.capabilities:
            capabilities_by_owner[capability.owner_node_id].append(capability.kind)

        scfg_nodes: list[SCFGNode] = []
        scfg_by_port: dict[str, SCFGNode] = {}
        for port in capabilities.ports:
            owner = behavior_nodes.get(port.owner_node_id)
            if owner is None:
                continue
            node = SCFGNode(
                port_id=port.port_id,
                semantic_key=(
                    f"{port.owner_semantic_key}::{port.direction}::{port.data_type}"
                ),
                owner_node_id=port.owner_node_id,
                owner_semantic_key=port.owner_semantic_key,
                owner_file=owner.owner_file,
                direction=port.direction,
                data_type=port.data_type,
                trust_zone=port.trust_zone,
                capability_kinds=sorted(set(capabilities_by_owner[port.owner_node_id])),
                risk_tags=sorted(set(owner.risk_tags)),
                evidence=port.evidence,
            )
            scfg_nodes.append(node)
            scfg_by_port[node.port_id] = node

        def make_edge(
            source_port,
            target_port,
            source_owner: BehaviorNode,
            target_owner: BehaviorNode,
            relation: str,
            semantic_key: str,
            flow_kind: str,
            basis: str,
            certainty: str,
            risk_tags: list[str],
            evidence: list[EvidenceRef],
        ) -> SCFGEdge:
            source_zone = source_port.trust_zone if source_port else "UNKNOWN"
            target_zone = target_port.trust_zone if target_port else "UNKNOWN"
            boundary = (
                source_zone != target_zone
                and source_zone != "UNCLASSIFIED"
                and target_zone != "UNCLASSIFIED"
            )
            source_id = source_port.port_id if source_port else None
            target_id = target_port.port_id if target_port else None
            identity = [semantic_key, source_id, target_id, flow_kind]
            return SCFGEdge(
                edge_id=_stable_id("scfg-edge", identity),
                semantic_key=semantic_key,
                source_port_id=source_id,
                target_port_id=target_id,
                source_node_id=source_owner.node_id,
                target_node_id=target_owner.node_id,
                relation=relation,
                flow_kind=flow_kind,
                basis=basis,
                certainty=certainty,
                source_trust_zone=source_zone,
                target_trust_zone=target_zone,
                crosses_trust_boundary=boundary,
                risk_tags=sorted(set(risk_tags)),
                evidence=_unique_evidence(evidence),
            )

        edges: list[SCFGEdge] = []
        unresolved = 0
        reads_by_function: dict[str, list] = defaultdict(list)
        outputs_by_function: dict[str, list] = defaultdict(list)
        for edge in graph.edges:
            source_owner = behavior_nodes[edge.source_id]
            target_owner = behavior_nodes[edge.target_id]
            source_ports = ports_by_owner.get(edge.source_id, [])
            target_ports = ports_by_owner.get(edge.target_id, [])
            source_port = None
            target_port = None
            flow_kind = "UNKNOWN_FLOW"
            if edge.relation == "READS":
                source_port = self._select_port(target_ports, ("SOURCE", "TRANSFORM"))
                target_port = self._select_port(source_ports, ("SOURCE", "TRANSFORM"))
                # READS flows from the data object into the reader function.
                edge_source_owner, edge_target_owner = target_owner, source_owner
                flow_kind = "DATA_FLOW"
                if source_owner.kind == "Function":
                    reads_by_function[source_owner.node_id].append(edge)
            elif edge.relation == "WRITES":
                source_port = self._select_port(source_ports, ("SINK", "TRANSFORM"))
                target_port = self._select_port(target_ports, ("SINK", "SOURCE"))
                flow_kind = "DATA_FLOW"
                if source_owner.kind == "Function":
                    outputs_by_function[source_owner.node_id].append(edge)
            elif edge.relation == "CONNECTS_TO":
                source_port = self._select_port(source_ports, ("SINK", "TRANSFORM"))
                target_port = self._select_port(target_ports, ("SINK", "SOURCE"))
                flow_kind = "NETWORK_FLOW"
                if source_owner.kind == "Function":
                    outputs_by_function[source_owner.node_id].append(edge)
            elif edge.relation == "CALLS":
                source_port = self._select_port(source_ports, ("CONTROL", "SINK"))
                target_port = self._select_port(target_ports, ("CONTROL", "SOURCE"))
                flow_kind = "CONTROL_FLOW"
            elif edge.relation == "INVOKES":
                source_port = self._select_port(source_ports, ("CONTROL", "SINK"))
                target_port = self._select_port(target_ports, ("CONTROL", "SINK"))
                flow_kind = (
                    "PROCESS_FLOW"
                    if "PROCESS_EXECUTION" in target_owner.risk_tags
                    else "TOOL_FLOW"
                )
            elif edge.relation == "GRANTS":
                source_port = self._select_port(source_ports, ("CONTROL",))
                target_port = self._select_port(target_ports, ("CONTROL", "SINK"))
                flow_kind = "PRIVILEGE_FLOW"
            elif edge.relation == "INSTRUCTS":
                source_port = self._select_port(source_ports, ("CONTROL",))
                target_port = self._select_port(target_ports, ("CONTROL", "TRANSFORM"))
                flow_kind = "INSTRUCTION_FLOW"
            elif edge.relation == "REFERENCES":
                source_port = self._select_port(source_ports, ("CONTROL", "TRANSFORM"))
                target_port = self._select_port(target_ports, ("CONTROL", "TRANSFORM"))
                flow_kind = "REFERENCE_FLOW"

            if source_port is None or target_port is None:
                unresolved += 1
                certainty = "UNRESOLVED"
            else:
                certainty = "DIRECT_STATIC"
            if edge.relation != "READS":
                edge_source_owner, edge_target_owner = source_owner, target_owner
            edges.append(
                make_edge(
                    source_port, target_port, edge_source_owner, edge_target_owner,
                    edge.relation, edge.semantic_key, flow_kind, edge.basis,
                    certainty, edge.risk_tags, [
                        EvidenceRef(
                            snapshot=item.snapshot, file=item.file,
                            start_line=item.start_line, end_line=item.end_line,
                            excerpt=item.excerpt, basis=item.basis,
                            producer=item.producer,
                        )
                        for item in edge.evidence
                    ],
                )
            )

        # A function-scope may-flow is a conservative candidate, not proof that
        # every read value reaches every network/write operation in that function.
        for function_id, read_edges in reads_by_function.items():
            output_edges = outputs_by_function.get(function_id, [])
            if not output_edges:
                continue
            function = behavior_nodes[function_id]
            function_ports = ports_by_owner.get(function_id, [])
            input_port = self._select_port(function_ports, ("SOURCE",))
            output_port = self._select_port(function_ports, ("SINK",))
            if input_port is None or output_port is None:
                unresolved += 1
                continue
            supporting = [*read_edges, *output_edges]
            evidence = _unique_evidence(
                EvidenceRef(
                    snapshot=item.snapshot, file=item.file,
                    start_line=item.start_line, end_line=item.end_line,
                    excerpt=item.excerpt, basis=item.basis, producer=item.producer,
                )
                for edge in supporting for item in edge.evidence
            )
            edges.append(
                make_edge(
                    input_port, output_port, function, function,
                    "FUNCTION_SCOPE_MAY_FLOW",
                    f"function-may-flow:{function.semantic_key}",
                    "DATA_FLOW", "RULE_INFERENCE", "POSSIBLE",
                    ["POSSIBLE_DATA_PROPAGATION"], evidence,
                )
            )

        coverage = capabilities.coverage
        if unresolved and coverage == "COMPLETE_FOR_GRAPH":
            coverage = "PARTIAL"
        graph_id = _stable_id(
            "scfg",
            [
                graph.snapshot_sha256,
                sorted(node.semantic_key for node in scfg_nodes),
                sorted(edge.semantic_key for edge in edges),
            ],
        )
        return SCFGGraph(
            graph_id=graph_id,
            source_behavior_graph_id=graph.snapshot_id,
            source_snapshot_sha256=graph.snapshot_sha256,
            nodes=sorted(scfg_nodes, key=lambda item: item.port_id),
            edges=sorted(edges, key=lambda item: item.edge_id),
            coverage=coverage,
            unresolved_edge_count=unresolved,
            limitations=[
                "SCFG edges are derived from static P12 relations, not runtime traces.",
                "FUNCTION_SCOPE_MAY_FLOW is an over-approximation marked POSSIBLE.",
                "Argument/return-value binding, reflection, aliases and implicit flows are not resolved.",
            ],
        )
