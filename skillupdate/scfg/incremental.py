"""Version alignment and incremental differencing for SCFG ports and edges."""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict

from skillupdate.behavior_graph.models import BehavioralGraphDelta

from .models import (
    SCFGComponentChange, SCFGDelta, SCFGEdge, SCFGEdgeAlignment,
    SCFGGraph, SCFGNode, SCFGPortAlignment,
)


def _stable_id(prefix: str, payload: object) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:20]}"


def _node_payload(node: SCFGNode) -> dict:
    return node.model_dump(
        mode="json",
        exclude={"evidence", "port_id", "owner_node_id"},
    )


def _edge_payload(edge: SCFGEdge) -> dict:
    return edge.model_dump(
        mode="json",
        exclude={"evidence", "edge_id", "source_node_id", "target_node_id"},
    )


class SCFGIncrementalAnalyzer:
    """Aligns ports through P12 node alignment, then aligns flow edges."""

    def compare(
        self,
        old: SCFGGraph,
        new: SCFGGraph,
        behavior_delta: BehavioralGraphDelta | None = None,
    ) -> SCFGDelta:
        node_map = (
            {
                item.old_node_id: item.new_node_id
                for item in behavior_delta.node_alignments
            }
            if behavior_delta is not None
            else {}
        )
        old_by_owner: dict[str, list[SCFGNode]] = defaultdict(list)
        new_by_owner: dict[str, list[SCFGNode]] = defaultdict(list)
        for node in old.nodes:
            old_by_owner[node.owner_node_id].append(node)
        for node in new.nodes:
            new_by_owner[node.owner_node_id].append(node)

        port_alignments: list[SCFGPortAlignment] = []
        used_new_ports: set[str] = set()
        for old_node in old.nodes:
            expected_owner = node_map.get(old_node.owner_node_id, old_node.owner_node_id)
            candidates = [
                item for item in new.nodes
                if item.owner_node_id == expected_owner
                and item.direction == old_node.direction
                and item.data_type == old_node.data_type
                and item.port_id not in used_new_ports
            ]
            if not candidates:
                candidates = [
                    item for item in new.nodes
                    if item.owner_semantic_key == old_node.owner_semantic_key
                    and item.direction == old_node.direction
                    and item.data_type == old_node.data_type
                    and item.port_id not in used_new_ports
                ]
            if len(candidates) != 1:
                continue
            match = candidates[0]
            used_new_ports.add(match.port_id)
            port_alignments.append(
                SCFGPortAlignment(
                    old_port_id=old_node.port_id,
                    new_port_id=match.port_id,
                    method="ALIGNED_OWNER_AND_PORT",
                    evidence=[*old_node.evidence, *match.evidence],
                )
            )

        port_map = {
            item.old_port_id: item.new_port_id for item in port_alignments
        }
        candidates: dict[tuple[str, str, str], list[SCFGEdge]] = defaultdict(list)
        for edge in new.edges:
            if edge.source_port_id is None or edge.target_port_id is None:
                continue
            candidates[
                (edge.source_port_id, edge.target_port_id, edge.relation)
            ].append(edge)
        used_new_edges: set[str] = set()
        edge_alignments: list[SCFGEdgeAlignment] = []
        for old_edge in old.edges:
            if old_edge.source_port_id is None or old_edge.target_port_id is None:
                continue
            mapped_source = port_map.get(old_edge.source_port_id)
            mapped_target = port_map.get(old_edge.target_port_id)
            if mapped_source is None or mapped_target is None:
                continue
            matches = [
                item for item in candidates.get(
                    (mapped_source, mapped_target, old_edge.relation), []
                )
                if item.edge_id not in used_new_edges
            ]
            if not matches:
                continue
            exact = [
                item for item in matches
                if item.semantic_key == old_edge.semantic_key
                and item.flow_kind == old_edge.flow_kind
            ]
            match = exact[0] if exact else matches[0] if len(matches) == 1 else None
            if match is None:
                continue
            used_new_edges.add(match.edge_id)
            edge_alignments.append(
                SCFGEdgeAlignment(
                    old_edge_id=old_edge.edge_id,
                    new_edge_id=match.edge_id,
                    method="ALIGNED_PORTS_AND_RELATION",
                    evidence=[*old_edge.evidence, *match.evidence],
                )
            )

        old_node_ids = {item.port_id for item in old.nodes}
        new_node_ids = {item.port_id for item in new.nodes}
        aligned_old_ports = {item.old_port_id for item in port_alignments}
        aligned_new_ports = {item.new_port_id for item in port_alignments}
        added_nodes = [item for item in new.nodes if item.port_id not in aligned_new_ports]
        removed_nodes = [item for item in old.nodes if item.port_id not in aligned_old_ports]
        modified_nodes: list[SCFGComponentChange] = []
        old_node_by_id = {item.port_id: item for item in old.nodes}
        new_node_by_id = {item.port_id: item for item in new.nodes}
        for alignment in port_alignments:
            before = old_node_by_id[alignment.old_port_id]
            after = new_node_by_id[alignment.new_port_id]
            if _node_payload(before) != _node_payload(after):
                modified_nodes.append(
                    SCFGComponentChange(
                        entity_type="PORT",
                        change_type="MODIFIED",
                        semantic_key=after.semantic_key,
                        before=before.model_dump(mode="json"),
                        after=after.model_dump(mode="json"),
                        evidence=[*before.evidence, *after.evidence],
                    )
                )

        aligned_old_edges = {item.old_edge_id for item in edge_alignments}
        aligned_new_edges = {item.new_edge_id for item in edge_alignments}
        added_edges = [item for item in new.edges if item.edge_id not in aligned_new_edges]
        removed_edges = [item for item in old.edges if item.edge_id not in aligned_old_edges]
        old_edge_by_id = {item.edge_id: item for item in old.edges}
        new_edge_by_id = {item.edge_id: item for item in new.edges}
        modified_edges: list[SCFGComponentChange] = []
        for alignment in edge_alignments:
            before = old_edge_by_id[alignment.old_edge_id]
            after = new_edge_by_id[alignment.new_edge_id]
            if _edge_payload(before) != _edge_payload(after):
                modified_edges.append(
                    SCFGComponentChange(
                        entity_type="FLOW_EDGE",
                        change_type="MODIFIED",
                        semantic_key=after.semantic_key,
                        before=before.model_dump(mode="json"),
                        after=after.model_dump(mode="json"),
                        evidence=[*before.evidence, *after.evidence],
                    )
                )

        coverage = (
            "UNKNOWN"
            if old.coverage == "UNKNOWN" or new.coverage == "UNKNOWN"
            else "PARTIAL"
            if old.coverage == "PARTIAL" or new.coverage == "PARTIAL"
            else "COMPLETE_FOR_GRAPH"
        )
        limitations = sorted(set([*old.limitations, *new.limitations]))
        return SCFGDelta(
            old_graph=old,
            new_graph=new,
            port_alignments=port_alignments,
            edge_alignments=edge_alignments,
            added_nodes=added_nodes,
            removed_nodes=removed_nodes,
            modified_nodes=modified_nodes,
            added_edges=added_edges,
            removed_edges=removed_edges,
            modified_edges=modified_edges,
            summary={
                "added_ports": len(added_nodes),
                "removed_ports": len(removed_nodes),
                "modified_ports": len(modified_nodes),
                "added_edges": len(added_edges),
                "removed_edges": len(removed_edges),
                "modified_edges": len(modified_edges),
            },
            coverage=coverage,
            limitations=limitations,
        )
