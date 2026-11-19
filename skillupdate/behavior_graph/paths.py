"""Semantic risk-path rules; graph set differences alone never create a path."""

from __future__ import annotations

from collections import defaultdict, deque

from skillupdate.hsda.common import stable_id

from .models import BehaviorEdge, BehaviorGraph, GraphEvidence, RiskPath


def _evidence(edges: list[BehaviorEdge]) -> list[GraphEvidence]:
    unique: dict[str, GraphEvidence] = {}
    for edge in edges:
        for item in edge.evidence:
            unique[item.model_dump_json()] = item
    return list(unique.values())


def find_new_risk_paths(
    graph: BehaviorGraph,
    added_node_ids: set[str],
    added_edge_ids: set[str],
) -> list[RiskPath]:
    nodes = {node.node_id: node for node in graph.nodes}
    outgoing: dict[str, list[BehaviorEdge]] = defaultdict(list)
    for edge in graph.edges:
        outgoing[edge.source_id].append(edge)
    paths: list[RiskPath] = []

    def add_path(
        pattern: str,
        node_ids: list[str],
        edges: list[BehaviorEdge],
        risk_types: list[str],
        explanation: str,
    ) -> None:
        components = set(node_ids) | {edge.edge_id for edge in edges}
        added = sorted(components & (added_node_ids | added_edge_ids))
        if not added:
            return
        owners = {nodes[node_id].owner_file for node_id in node_ids}
        paths.append(
            RiskPath(
                path_id=f"p-{stable_id(pattern, *sorted(nodes[item].semantic_key for item in node_ids), *sorted(edge.relation for edge in edges))}",
                pattern=pattern,
                node_ids=node_ids,
                edge_ids=[edge.edge_id for edge in edges],
                risk_types=sorted(set(risk_types)),
                explanation=explanation,
                evidence=_evidence(edges),
                added_component_ids=added,
                cross_file=len(owners) > 1,
            )
        )

    call_paths: dict[str, dict[str, list[BehaviorEdge]]] = {}
    function_ids = {node.node_id for node in graph.nodes if node.kind == "Function"}
    for root in function_ids:
        reached: dict[str, list[BehaviorEdge]] = {root: []}
        queue = deque([root])
        while queue:
            current = queue.popleft()
            if len(reached[current]) >= 6:
                continue
            for edge in outgoing.get(current, []):
                if edge.relation != "CALLS" or edge.target_id in reached:
                    continue
                reached[edge.target_id] = [*reached[current], edge]
                queue.append(edge.target_id)
        call_paths[root] = reached

    for source_id, edges in outgoing.items():
        source = nodes[source_id]
        if source.kind == "Function":
            reached = call_paths.get(source_id, {source_id: []})
            read_pairs: list[tuple[list[BehaviorEdge], BehaviorEdge]] = []
            endpoint_pairs: list[tuple[list[BehaviorEdge], BehaviorEdge]] = []
            for function_id, prefix in reached.items():
                for candidate in outgoing.get(function_id, []):
                    if (
                        candidate.relation == "READS"
                        and "SENSITIVE_DATA" in nodes[candidate.target_id].risk_tags
                    ):
                        read_pairs.append((prefix, candidate))
                    if candidate.relation == "CONNECTS_TO":
                        endpoint_pairs.append((prefix, candidate))
            for read_prefix, read_edge in read_pairs:
                for endpoint_prefix, endpoint_edge in endpoint_pairs:
                    combined_edges = [
                        *read_prefix,
                        read_edge,
                        *endpoint_prefix,
                        endpoint_edge,
                    ]
                    ordered_nodes: list[str] = [source_id]
                    for candidate in combined_edges:
                        if candidate.source_id not in ordered_nodes:
                            ordered_nodes.append(candidate.source_id)
                        if candidate.target_id not in ordered_nodes:
                            ordered_nodes.append(candidate.target_id)
                    add_path(
                        "SENSITIVE_DATA_TO_ENDPOINT",
                        ordered_nodes,
                        combined_edges,
                        ["SENSITIVE_DATA_ACCESS", "DATA_TRANSMISSION_INTENT"],
                        "A function and its statically resolved call closure can read sensitive data and connect to an endpoint; this is a rule inference, not observed transmission.",
                    )
        for edge in edges:
            target = nodes[edge.target_id]
            if edge.relation == "INVOKES" and "PROCESS_EXECUTION" in target.risk_tags:
                add_path(
                    "PROCESS_TOOL_INVOCATION",
                    [source_id, target.node_id],
                    [edge],
                    ["PROCESS_EXECUTION"],
                    "Static call evidence links code to a process-related tool.",
                )
            if (
                source.kind == "Instruction"
                and edge.relation == "INSTRUCTS"
                and target.risk_tags
            ):
                add_path(
                    "INSTRUCTION_TO_RISK_CAPABILITY",
                    [source_id, target.node_id],
                    [edge],
                    target.risk_tags,
                    "An instruction statically names a risk-relevant capability.",
                )
            if (
                source.kind == "Permission"
                and edge.relation == "GRANTS"
                and target.risk_tags
            ):
                add_path(
                    "PERMISSION_ENABLES_RISK_CAPABILITY",
                    [source_id, target.node_id],
                    [edge],
                    target.risk_tags,
                    "A configuration permission statically enables a risk-relevant capability.",
                )

    for instruction in (node for node in graph.nodes if node.kind == "Instruction"):
        queue: deque[tuple[str, list[BehaviorEdge]]] = deque(
            [(instruction.node_id, [])]
        )
        visited = {instruction.node_id}
        while queue:
            current, prefix = queue.popleft()
            if len(prefix) >= 7:
                continue
            for edge in outgoing.get(current, []):
                target = nodes[edge.target_id]
                candidate_path = [*prefix, edge]
                if edge.relation in {"INVOKES", "CONNECTS_TO", "READS"} and (
                    target.risk_tags or edge.risk_tags
                ):
                    ordered_nodes = [instruction.node_id]
                    for candidate in candidate_path:
                        if candidate.source_id not in ordered_nodes:
                            ordered_nodes.append(candidate.source_id)
                        if candidate.target_id not in ordered_nodes:
                            ordered_nodes.append(candidate.target_id)
                    add_path(
                        "INSTRUCTION_TO_RISK_CAPABILITY",
                        ordered_nodes,
                        candidate_path,
                        [*target.risk_tags, *edge.risk_tags]
                        or ["RISK_RELEVANT_CAPABILITY"],
                        "An instruction reaches a risk-relevant capability through static INSTRUCTS, REFERENCES, or CALLS relations.",
                    )
                if (
                    edge.relation in {"INSTRUCTS", "REFERENCES", "CALLS"}
                    and edge.target_id not in visited
                ):
                    visited.add(edge.target_id)
                    queue.append((edge.target_id, candidate_path))
    unique = {path.path_id: path for path in paths}
    return [unique[key] for key in sorted(unique)]
