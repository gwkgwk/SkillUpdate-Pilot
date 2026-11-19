"""Evidence-backed node and relation alignment across graph versions."""

from __future__ import annotations

from collections import defaultdict

from .models import (
    BehaviorEdge,
    BehaviorGraph,
    BehaviorNode,
    EdgeAlignment,
    NodeAlignment,
)


def align_nodes(old: BehaviorGraph, new: BehaviorGraph) -> list[NodeAlignment]:
    alignments: list[NodeAlignment] = []
    matched_old: set[str] = set()
    matched_new: set[str] = set()
    new_exact = {(node.kind, node.semantic_key): node for node in new.nodes}
    for old_node in old.nodes:
        new_node = new_exact.get((old_node.kind, old_node.semantic_key))
        if new_node is None:
            continue
        alignments.append(
            NodeAlignment(
                old_node_id=old_node.node_id,
                new_node_id=new_node.node_id,
                method="EXACT_SEMANTIC_KEY",
                confidence=1.0,
                evidence=[old_node.evidence[0], new_node.evidence[0]],
            )
        )
        matched_old.add(old_node.node_id)
        matched_new.add(new_node.node_id)

    def unique_by_attribute(
        nodes: list[BehaviorNode], kind: str, attribute: str, matched: set[str]
    ) -> dict[str, BehaviorNode]:
        groups: dict[str, list[BehaviorNode]] = defaultdict(list)
        for node in nodes:
            value = str(node.attributes.get(attribute, ""))
            if node.kind == kind and node.node_id not in matched and value:
                groups[value].append(node)
        return {value: items[0] for value, items in groups.items() if len(items) == 1}

    old_files = unique_by_attribute(old.nodes, "File", "content_sha256", matched_old)
    new_files = unique_by_attribute(new.nodes, "File", "content_sha256", matched_new)
    for digest in sorted(set(old_files) & set(new_files)):
        old_node, new_node = old_files[digest], new_files[digest]
        alignments.append(
            NodeAlignment(
                old_node_id=old_node.node_id,
                new_node_id=new_node.node_id,
                method="FILE_CONTENT_RENAME",
                confidence=1.0,
                evidence=[old_node.evidence[0], new_node.evidence[0]],
            )
        )
        matched_old.add(old_node.node_id)
        matched_new.add(new_node.node_id)

    old_functions = unique_by_attribute(
        old.nodes, "Function", "structure_fingerprint", matched_old
    )
    new_functions = unique_by_attribute(
        new.nodes, "Function", "structure_fingerprint", matched_new
    )
    for fingerprint in sorted(set(old_functions) & set(new_functions)):
        old_node, new_node = old_functions[fingerprint], new_functions[fingerprint]
        alignments.append(
            NodeAlignment(
                old_node_id=old_node.node_id,
                new_node_id=new_node.node_id,
                method="FUNCTION_STRUCTURE",
                confidence=0.95,
                evidence=[old_node.evidence[0], new_node.evidence[0]],
            )
        )
        matched_old.add(old_node.node_id)
        matched_new.add(new_node.node_id)
    return sorted(alignments, key=lambda item: (item.old_node_id, item.new_node_id))


def align_edges(
    old: BehaviorGraph,
    new: BehaviorGraph,
    node_alignments: list[NodeAlignment],
) -> list[EdgeAlignment]:
    node_map = {item.old_node_id: item.new_node_id for item in node_alignments}
    candidates: dict[tuple[str, str, str], list[BehaviorEdge]] = defaultdict(list)
    for edge in new.edges:
        candidates[(edge.source_id, edge.relation, edge.target_id)].append(edge)
    used_new: set[str] = set()
    alignments: list[EdgeAlignment] = []
    for old_edge in old.edges:
        source = node_map.get(old_edge.source_id)
        target = node_map.get(old_edge.target_id)
        if source is None or target is None:
            continue
        matches = [
            edge
            for edge in candidates.get((source, old_edge.relation, target), [])
            if edge.edge_id not in used_new
        ]
        if not matches:
            continue
        exact = [edge for edge in matches if edge.semantic_key == old_edge.semantic_key]
        if exact:
            new_edge = exact[0]
        elif len(matches) == 1:
            new_edge = matches[0]
        else:
            continue
        used_new.add(new_edge.edge_id)
        alignments.append(
            EdgeAlignment(
                old_edge_id=old_edge.edge_id,
                new_edge_id=new_edge.edge_id,
                method="ALIGNED_ENDPOINTS_AND_RELATION",
                evidence=[old_edge.evidence[0], new_edge.evidence[0]],
            )
        )
    return sorted(alignments, key=lambda item: (item.old_edge_id, item.new_edge_id))
