"""Bounded risk-path enumeration over SCFG trust zones and flow semantics."""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque

from skillupdate.capability.models import EvidenceRef

from .models import SCFGDelta, SCFGEdge, SCFGGraph, SCFGNode, SCFGRiskPath, SCFGPathAnalysis

DATA_PATH_KINDS = {"DATA_FLOW", "NETWORK_FLOW"}
RISKY_CAPABILITIES = {
    "FILE_WRITE", "NETWORK_CONNECT", "PROCESS_EXECUTION",
    "TOOL_INVOCATION", "PERMISSION_GRANT", "DATA_TRANSFER",
}


def _stable_id(prefix: str, payload: object) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:20]}"


def _evidence(nodes: list[SCFGNode], edges: list[SCFGEdge]) -> list[EvidenceRef]:
    found = {
        item.model_dump_json(): item
        for node in nodes for item in node.evidence
    }
    found.update({
        item.model_dump_json(): item
        for edge in edges for item in edge.evidence
    })
    return [found[key] for key in sorted(found)]


class SCFGPathAnalyzer:
    """Finds candidate security flows; paths are rule inferences, not execution."""

    def __init__(self, *, max_depth: int = 10, max_paths: int = 256) -> None:
        if max_depth < 2 or max_paths < 1:
            raise ValueError("max_depth and max_paths must be positive bounds")
        self.max_depth = max_depth
        self.max_paths = max_paths

    def _sensitive_external_paths(
        self, graph: SCFGGraph
    ) -> tuple[list[SCFGRiskPath], int, bool]:
        nodes = {item.port_id: item for item in graph.nodes}
        outgoing: dict[str, list[SCFGEdge]] = defaultdict(list)
        for edge in graph.edges:
            if (
                edge.source_port_id is not None
                and edge.target_port_id is not None
                and edge.flow_kind in DATA_PATH_KINDS
            ):
                outgoing[edge.source_port_id].append(edge)
        starts = [
            item for item in graph.nodes
            if item.direction == "SOURCE"
            and (
                item.trust_zone == "SENSITIVE"
                or "SENSITIVE_DATA" in item.risk_tags
            )
        ]
        sinks = {
            item.port_id for item in graph.nodes
            if item.trust_zone == "UNTRUSTED_EXTERNAL"
            or item.data_type == "NETWORK"
        }
        results: dict[str, SCFGRiskPath] = {}
        explored = 0
        truncated = False
        for start in starts:
            queue = deque([(start.port_id, [start.port_id], [])])
            while queue:
                current, port_ids, edge_path = queue.popleft()
                explored += 1
                if explored > self.max_paths * self.max_depth * max(1, len(starts)):
                    truncated = True
                    return list(results.values()), explored, truncated
                if len(edge_path) >= self.max_depth:
                    continue
                for edge in sorted(
                    outgoing.get(current, []), key=lambda item: item.edge_id
                ):
                    target = edge.target_port_id
                    if target in port_ids:
                        continue
                    next_ports = [*port_ids, target]
                    next_edges = [*edge_path, edge]
                    if target in sinks and any(
                        item.flow_kind == "NETWORK_FLOW" for item in next_edges
                    ):
                        path_nodes = [nodes[item] for item in next_ports]
                        signature = [
                            [item.semantic_key for item in path_nodes],
                            [item.semantic_key for item in next_edges],
                        ]
                        path_id = _stable_id("scfg-path", ["SENSITIVE_DATA_TO_EXTERNAL", signature])
                        results[path_id] = SCFGRiskPath(
                            path_id=path_id,
                            pattern="SENSITIVE_DATA_TO_EXTERNAL",
                            port_ids=next_ports,
                            owner_node_ids=list(dict.fromkeys(
                                item.owner_node_id for item in path_nodes
                            )),
                            edge_ids=[item.edge_id for item in next_edges],
                            risk_types=["SENSITIVE_DATA_ACCESS", "DATA_TRANSMISSION_INTENT"],
                            severity="CRITICAL",
                            crosses_trust_boundary=any(
                                item.crosses_trust_boundary for item in next_edges
                            ),
                            is_new=False,
                            explanation=(
                                "A statically modeled sensitive-data source can reach "
                                "an external network sink through a possible function flow. "
                                "This is a candidate path, not proof of transmission."
                            ),
                            evidence=_evidence(path_nodes, next_edges),
                        )
                        if len(results) >= self.max_paths:
                            truncated = True
                            return list(results.values()), explored, truncated
                    else:
                        queue.append((target, next_ports, next_edges))
        return [results[key] for key in sorted(results)], explored, truncated

    def _direct_capability_paths(self, graph: SCFGGraph) -> list[SCFGRiskPath]:
        nodes = {item.port_id: item for item in graph.nodes}
        results: dict[str, SCFGRiskPath] = {}
        for edge in graph.edges:
            if edge.source_port_id is None or edge.target_port_id is None:
                continue
            target = nodes.get(edge.target_port_id)
            source = nodes.get(edge.source_port_id)
            if target is None or source is None:
                continue
            pattern = None
            severity = None
            risks: list[str] = []
            explanation = ""
            if edge.flow_kind == "PROCESS_FLOW" or (
                "PROCESS_EXECUTION" in target.risk_tags
            ):
                pattern = "PROCESS_EXECUTION"
                severity = "HIGH"
                risks = ["PROCESS_EXECUTION"]
                explanation = "A static invocation relation reaches a process-related capability."
            elif edge.flow_kind == "INSTRUCTION_FLOW" and (
                set(target.capability_kinds) & RISKY_CAPABILITIES
                or set(target.risk_tags) & RISKY_CAPABILITIES
            ):
                pattern = "INSTRUCTION_TO_RISK_CAPABILITY"
                severity = "MEDIUM"
                risks = sorted(set(target.risk_tags) | set(target.capability_kinds))
                explanation = "An instruction node points to a risk-relevant capability."
            elif edge.flow_kind == "PRIVILEGE_FLOW" and (
                set(target.capability_kinds) & RISKY_CAPABILITIES
                or set(target.risk_tags) & RISKY_CAPABILITIES
            ):
                pattern = "PRIVILEGE_TO_RISK_CAPABILITY"
                severity = "HIGH"
                risks = sorted(set(target.risk_tags) | set(target.capability_kinds))
                explanation = "A permission relation enables a risk-relevant capability."
            if pattern is None:
                continue
            signature = [pattern, source.semantic_key, edge.semantic_key, target.semantic_key]
            path_id = _stable_id("scfg-path", signature)
            results[path_id] = SCFGRiskPath(
                path_id=path_id,
                pattern=pattern,
                port_ids=[source.port_id, target.port_id],
                owner_node_ids=list(dict.fromkeys([
                    source.owner_node_id, target.owner_node_id
                ])),
                edge_ids=[edge.edge_id],
                risk_types=risks or [pattern],
                severity=severity,
                crosses_trust_boundary=edge.crosses_trust_boundary,
                is_new=False,
                explanation=explanation,
                evidence=_evidence([source, target], [edge]),
            )
        return [results[key] for key in sorted(results)]

    def _enumerate(self, graph: SCFGGraph):
        sensitive, explored, truncated = self._sensitive_external_paths(graph)
        direct = self._direct_capability_paths(graph)
        merged = {item.path_id: item for item in [*sensitive, *direct]}
        return [merged[key] for key in sorted(merged)], explored, truncated

    def analyze(self, delta: SCFGDelta) -> SCFGPathAnalysis:
        old_paths, old_explored, old_truncated = self._enumerate(delta.old_graph)
        new_paths, new_explored, new_truncated = self._enumerate(delta.new_graph)
        old_by_id = {item.path_id: item for item in old_paths}
        new_by_id = {item.path_id: item for item in new_paths}
        added_edge_ids = {item.edge_id for item in delta.added_edges}
        added_edge_ids.update(
            str(item.after.get("edge_id"))
            for item in delta.modified_edges if item.after
        )
        added_port_ids = {item.port_id for item in delta.added_nodes}
        added_port_ids.update(
            str(item.after.get("port_id"))
            for item in delta.modified_nodes if item.after
        )
        added: list[SCFGRiskPath] = []
        persistent: list[SCFGRiskPath] = []
        for path_id, path in new_by_id.items():
            introduced = sorted(
                (set(path.edge_ids) & added_edge_ids)
                | (set(path.port_ids) & added_port_ids)
            )
            is_new = path_id not in old_by_id or bool(introduced)
            updated = path.model_copy(
                update={"is_new": is_new, "introduced_component_ids": introduced}
            )
            if is_new:
                added.append(updated)
            else:
                persistent.append(updated)
        removed = [
            item.model_copy(update={"is_new": False})
            for path_id, item in old_by_id.items() if path_id not in new_by_id
        ]
        coverage = (
            "UNKNOWN" if delta.coverage == "UNKNOWN"
            else "PARTIAL" if delta.coverage == "PARTIAL" or old_truncated or new_truncated
            else "COMPLETE_FOR_GRAPH"
        )
        return SCFGPathAnalysis(
            old_paths=old_paths,
            new_paths=[*added, *persistent],
            added_paths=added,
            removed_paths=removed,
            persistent_paths=persistent,
            coverage=coverage,
            truncated=old_truncated or new_truncated,
            explored_states=old_explored + new_explored,
            limitations=[
                "Path existence is a static/rule-based possibility, not runtime observation.",
                "Function-scope propagation deliberately over-approximates within-function flows.",
                "No interprocedural argument/return taint, reflection, alias or implicit-flow analysis is claimed.",
                "A path absent from this graph is not proof that the corresponding behavior is impossible.",
            ],
        )
