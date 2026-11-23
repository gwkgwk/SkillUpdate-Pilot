"""Conservative adapter from P12 behavioral graphs to P16-A capabilities."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .models import (
    Capability, CapabilityChange, CapabilityDelta, CapabilityEffect,
    CapabilityPort, CapabilitySnapshot, EvidenceRef, TrustBoundary,
)

RISK_MAP = {
    "FILE_OPERATION": "FILE_READ",
    "FILE_ACCESS": "FILE_READ",
    "FILE_READ": "FILE_READ",
    "FILE_WRITE": "FILE_WRITE",
    "NETWORK_OPERATION": "NETWORK_CONNECT",
    "EXTERNAL_REFERENCE": "NETWORK_CONNECT",
    "EXTERNAL_ENDPOINT": "NETWORK_CONNECT",
    "NETWORK_ENDPOINT": "NETWORK_CONNECT",
    "NETWORK_ACCESS": "NETWORK_CONNECT",
    "PROCESS_OPERATION": "PROCESS_EXECUTION",
    "PROCESS_EXECUTION": "PROCESS_EXECUTION",
    "SENSITIVE_DATA": "DATA_ACCESS",
    "SENSITIVE_DATA_ACCESS": "DATA_ACCESS",
    "DATA_TRANSMISSION": "DATA_TRANSFER",
    "DATA_TRANSMISSION_INTENT": "DATA_TRANSFER",
    "TOOL_INVOCATION": "TOOL_INVOCATION",
    "PERMISSION_CHANGE": "PERMISSION_GRANT",
    "PERMISSION_ENABLEMENT": "PERMISSION_GRANT",
    "PERMISSION_ALLOW": "PERMISSION_GRANT",
    "DEPENDENCY_CHANGE": "DEPENDENCY",
    "DEPENDENCY": "DEPENDENCY",
    "SECURITY_INSTRUCTION": "INSTRUCTION",
}
SENSITIVE_TAGS = {
    "SENSITIVE_DATA", "CREDENTIAL", "SECRET", "TOKEN", "PASSWORD", "PRIVATE_KEY"
}


def _dump(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return value
    raise TypeError("expected a Pydantic model or dictionary")


def _stable_id(prefix: str, value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:20]}"


def _evidence(items: list[dict[str, Any]]) -> list[EvidenceRef]:
    found: dict[str, EvidenceRef] = {}
    for item in items:
        for raw in item.get("evidence", []):
            evidence = EvidenceRef(
                snapshot=raw["snapshot"],
                file=raw["file"],
                start_line=raw["start_line"],
                end_line=raw["end_line"],
                excerpt=raw.get("excerpt", ""),
                basis=raw.get("basis", "UNKNOWN"),
                producer=raw.get("producer", ""),
            )
            key = json.dumps(evidence.model_dump(mode="json"), sort_keys=True)
            found[key] = evidence
    return [found[key] for key in sorted(found)]


def _tags(node: dict[str, Any]) -> set[str]:
    attrs = node.get("attributes", {})
    values = [*node.get("risk_tags", []), attrs.get("risk_type", "")]
    if isinstance(attrs.get("capabilities"), list):
        values.extend(attrs["capabilities"])
    return {str(value).upper() for value in values if value}


def _classify(node: dict[str, Any]) -> set[str]:
    tags = _tags(node)
    result = {RISK_MAP[tag] for tag in tags if tag in RISK_MAP}
    label = f'{node.get("label", "")} {node.get("semantic_key", "")}'.lower()
    kind = node.get("kind")
    if kind == "Instruction":
        result.add("INSTRUCTION")
    if kind == "Permission":
        result.add("PERMISSION_GRANT")
    if kind == "Endpoint" or node.get("attributes", {}).get("external") is True:
        result.add("NETWORK_CONNECT")
    if kind == "Tool":
        result.add("TOOL_INVOCATION")
    if re.search(r"\b(open|read_text|read_bytes|read_file)\b", label):
        result.add("FILE_READ")
    if re.search(r"\b(write_text|write_bytes|unlink|remove)\b", label):
        result.add("FILE_WRITE")
    if re.search(r"\b(subprocess|popen|exec|system)\b", label):
        result.add("PROCESS_EXECUTION")
    if not result and kind == "Data":
        result.add("DATA_ACCESS")
    return result or ({"UNKNOWN"} if kind in {"Function", "Tool"} else set())


def _trust_zone(node: dict[str, Any]) -> str:
    attrs = node.get("attributes", {})
    if attrs.get("trust_zone"):
        return str(attrs["trust_zone"]).upper()
    if _tags(node) & SENSITIVE_TAGS or attrs.get("sensitive") is True:
        return "SENSITIVE"
    if node.get("kind") == "Endpoint" or attrs.get("external") is True:
        return "UNTRUSTED_EXTERNAL"
    if node.get("kind") == "Permission":
        return "PRIVILEGED"
    if node.get("kind") in {"Function", "File", "Instruction", "Tool"}:
        return "SKILL_LOCAL"
    return "UNCLASSIFIED"


def _make_ports(node: dict[str, Any], evidence: list[EvidenceRef]) -> list[CapabilityPort]:
    port_specs = {
        "Data": [("SOURCE", "DATA"), ("SINK", "DATA")],
        "Endpoint": [("SINK", "NETWORK")],
        "Permission": [("CONTROL", "PERMISSION")],
        "Tool": [("SINK", "TOOL"), ("CONTROL", "TOOL")],
        "Function": [
            ("SOURCE", "INPUT"), ("SINK", "OUTPUT"),
            ("TRANSFORM", "VALUE"), ("CONTROL", "CALL"),
        ],
        "File": [
            ("SOURCE", "INPUT"), ("SINK", "OUTPUT"),
            ("TRANSFORM", "VALUE"), ("CONTROL", "REFERENCE"),
        ],
        "Instruction": [("CONTROL", "INSTRUCTION")],
    }
    specs = port_specs.get(node.get("kind"), [("CONTROL", "UNKNOWN")])
    return [
        CapabilityPort(
            port_id=_stable_id(
                "port", [node["semantic_key"], direction, data_type]
            ),
            owner_node_id=node["node_id"],
            owner_semantic_key=node["semantic_key"],
            direction=direction,
            data_type=data_type,
            trust_zone=_trust_zone(node),
            attributes={"node_kind": node.get("kind", "")},
            evidence=evidence,
        )
        for direction, data_type in specs
    ]


def _comparison_payload(item: Any) -> dict[str, Any]:
    payload = item.model_dump(mode="json", exclude={"evidence"})
    for field in ("capability_id", "port_id", "effect_id", "boundary_id"):
        payload.pop(field, None)
    return payload


class CapabilityAnalyzer:
    """Static evidence adapter; it never executes Skill code or claims runtime success."""

    def analyze(self, graph: Any, hsda_report: Any | None = None) -> CapabilitySnapshot:
        raw = _dump(graph)
        nodes = raw.get("nodes", [])
        edges = raw.get("edges", [])
        capabilities: list[Capability] = []
        ports: list[CapabilityPort] = []
        boundaries: list[TrustBoundary] = []
        node_ports: dict[str, list[CapabilityPort]] = {}
        for node in nodes:
            evidence = _evidence([node])
            if not evidence:
                continue
            for kind in sorted(_classify(node)):
                semantic_key = f'{node["semantic_key"]}::{kind}'
                capabilities.append(
                    Capability(
                        capability_id=_stable_id("cap", semantic_key),
                        semantic_key=semantic_key,
                        kind=kind,
                        label=node.get("label", node["semantic_key"]),
                        owner_node_id=node["node_id"],
                        owner_file=node.get("owner_file", ""),
                        risk_tags=sorted(_tags(node)),
                        attributes={"source_node_kind": node.get("kind", "")},
                        evidence=evidence,
                    )
                )
            made_ports = _make_ports(node, evidence)
            ports.extend(made_ports)
            node_ports[node["node_id"]] = made_ports
            zone = _trust_zone(node)
            if zone in {"SENSITIVE", "UNTRUSTED_EXTERNAL", "PRIVILEGED"}:
                boundary_kind = (
                    "SENSITIVE_DATA" if zone == "SENSITIVE"
                    else "EXTERNAL_ENDPOINT" if zone == "UNTRUSTED_EXTERNAL"
                    else "PRIVILEGE"
                )
                boundaries.append(
                    TrustBoundary(
                        boundary_id=_stable_id(
                            "boundary", [node["semantic_key"], boundary_kind]
                        ),
                        boundary_kind=boundary_kind,
                        node_id=node["node_id"],
                        semantic_key=node["semantic_key"],
                        trust_zone=zone,
                        rationale=(
                            f"Node classified into {zone} by P12 node semantics "
                            "or explicit attributes."
                        ),
                        evidence=evidence,
                    )
                )

        effects: list[CapabilityEffect] = []
        node_by_id = {node["node_id"]: node for node in nodes}
        for edge in edges:
            evidence = _evidence([edge])
            if not evidence:
                continue
            source = node_by_id[edge["source_id"]]
            target = node_by_id[edge["target_id"]]
            semantic_key = "::".join(
                [source["semantic_key"], edge["relation"], target["semantic_key"],
                 edge["semantic_key"]]
            )
            source_candidates = node_ports.get(edge["source_id"], [])
            target_candidates = node_ports.get(edge["target_id"], [])
            source_port = next(
                (p for p in source_candidates if p.direction in {"SINK", "CONTROL", "TRANSFORM"}),
                source_candidates[0] if source_candidates else None,
            )
            target_port = next(
                (p for p in target_candidates if p.direction in {"SOURCE", "SINK", "CONTROL", "TRANSFORM"}),
                target_candidates[0] if target_candidates else None,
            )
            effects.append(
                CapabilityEffect(
                    effect_id=_stable_id("effect", semantic_key),
                    semantic_key=semantic_key,
                    source_port_id=source_port.port_id if source_port else None,
                    target_port_id=target_port.port_id if target_port else None,
                    source_node_id=edge["source_id"],
                    target_node_id=edge["target_id"],
                    relation=edge["relation"],
                    effect_kind={
                        "READS": "DATA_READ", "WRITES": "DATA_WRITE",
                        "CONNECTS_TO": "NETWORK_FLOW", "GRANTS": "PRIVILEGE_FLOW",
                        "CALLS": "CALL_FLOW", "INVOKES": "TOOL_FLOW",
                        "INSTRUCTS": "INSTRUCTION_FLOW", "REFERENCES": "REFERENCE_FLOW",
                    }.get(edge["relation"], "UNKNOWN_FLOW"),
                    risk_tags=sorted(set(edge.get("risk_tags", []))),
                    evidence=evidence,
                )
            )

        represented = {port.owner_node_id for port in ports}
        coverage = (
            "COMPLETE_FOR_GRAPH"
            if len(represented) == len(nodes)
            else "PARTIAL"
        )
        if any(cap.kind == "UNKNOWN" for cap in capabilities):
            coverage = "PARTIAL"
        if hsda_report is not None:
            report = _dump(hsda_report)
            if report.get("unknown_changes") or report.get("issues"):
                coverage = "PARTIAL"
        source_sha = raw.get("snapshot_sha256", "")
        snapshot_id = _stable_id(
            "cap-snapshot",
            [source_sha, sorted(cap.semantic_key for cap in capabilities)],
        )
        return CapabilitySnapshot(
            snapshot_id=snapshot_id,
            source_snapshot_sha256=source_sha,
            capabilities=capabilities,
            ports=ports,
            effects=effects,
            trust_boundaries=boundaries,
            source_graph_node_count=len(nodes),
            source_graph_edge_count=len(edges),
            coverage=coverage,
        )

    def compare(
        self, old: CapabilitySnapshot, new: CapabilitySnapshot
    ) -> CapabilityDelta:
        changes: list[CapabilityChange] = []
        collections = [
            ("CAPABILITY", old.capabilities, new.capabilities, lambda x: x.semantic_key),
            (
                "PORT", old.ports, new.ports,
                lambda x: f"{x.owner_semantic_key}::{x.direction}::{x.data_type}",
            ),
            ("EFFECT", old.effects, new.effects, lambda x: x.semantic_key),
            (
                "TRUST_BOUNDARY", old.trust_boundaries, new.trust_boundaries,
                lambda x: f"{x.semantic_key}::{x.boundary_kind}",
            ),
        ]
        for entity_type, old_items, new_items, key_fn in collections:
            before = {key_fn(item): item for item in old_items}
            after = {key_fn(item): item for item in new_items}
            for key in sorted(set(before) | set(after)):
                old_item = before.get(key)
                new_item = after.get(key)
                if old_item is None:
                    change_type = "ADDED"
                elif new_item is None:
                    change_type = "REMOVED"
                elif _comparison_payload(old_item) != _comparison_payload(new_item):
                    change_type = "MODIFIED"
                else:
                    continue
                evidence = (
                    [*old_item.evidence, *new_item.evidence]
                    if old_item is not None and new_item is not None
                    else (new_item or old_item).evidence
                )
                changes.append(
                    CapabilityChange(
                        change_id=_stable_id("change", [entity_type, change_type, key]),
                        entity_type=entity_type,
                        change_type=change_type,
                        semantic_key=key,
                        before=old_item.model_dump(mode="json") if old_item else None,
                        after=new_item.model_dump(mode="json") if new_item else None,
                        evidence=evidence,
                    )
                )
        added = [item for item in changes if item.change_type == "ADDED"]
        removed = [item for item in changes if item.change_type == "REMOVED"]
        modified = [item for item in changes if item.change_type == "MODIFIED"]
        return CapabilityDelta(
            old_snapshot_id=old.snapshot_id,
            new_snapshot_id=new.snapshot_id,
            added=added,
            removed=removed,
            modified=modified,
            summary={
                "added": len(added), "removed": len(removed),
                "modified": len(modified),
            },
            limitations=[
                "Capabilities are inferred from static P12 graph semantics and evidence.",
                "A CONNECTS_TO edge does not prove successful data transmission.",
                "Dynamic dispatch, reflection, aliases and implicit flows are not resolved.",
            ],
        )
