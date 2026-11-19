"""Build the bounded, evidence-addressable package supplied to the LLM."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from skillupdate.behavior_graph.models import BehavioralGraphDelta, GraphEvidence
from skillupdate.hsda.models import HSDAReport, SourceLocation

from .models import AnalysisPackage, EvidenceCatalogItem


def _stable_id(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return f"ev-{hashlib.sha256(encoded).hexdigest()[:20]}"


def build_analysis_package(
    update_id: str,
    skill_metadata: dict[str, Any],
    old_function_summary: str,
    new_function_summary: str,
    hsda: HSDAReport,
    graph: BehavioralGraphDelta,
) -> AnalysisPackage:
    catalog: dict[str, EvidenceCatalogItem] = {}

    def add_location(
        location: SourceLocation | GraphEvidence,
        basis: str,
        producer: str,
    ) -> str:
        raw = {
            "snapshot": location.snapshot,
            "file": location.file,
            "start_line": location.start_line,
            "end_line": location.end_line,
            "excerpt": location.excerpt,
            "basis": basis,
            "producer": producer,
        }
        evidence_id = _stable_id(raw)
        catalog[evidence_id] = EvidenceCatalogItem(
            evidence_id=evidence_id,
            **raw,
        )
        return evidence_id

    def change_payload(change: Any) -> dict[str, Any]:
        payload = change.model_dump(mode="json", exclude={"evidence"})
        payload["evidence_ids"] = [
            add_location(item, "STATIC_FACT", f"HSDA:{change.analyzer}")
            for item in change.evidence
        ]
        return payload

    def graph_payload(source: Any) -> dict[str, Any]:
        nodes = []
        for node in source.nodes:
            payload = node.model_dump(mode="json", exclude={"evidence"})
            payload["evidence_ids"] = [
                add_location(item, item.basis, item.producer) for item in node.evidence
            ]
            nodes.append(payload)
        edges = []
        for edge in source.edges:
            payload = edge.model_dump(mode="json", exclude={"evidence"})
            payload["evidence_ids"] = [
                add_location(item, item.basis, item.producer) for item in edge.evidence
            ]
            edges.append(payload)
        return {
            "snapshot_id": source.snapshot_id,
            "snapshot_sha256": source.snapshot_sha256,
            "nodes": nodes,
            "edges": edges,
        }

    risk_paths = []
    for path in graph.new_risk_paths:
        payload = path.model_dump(mode="json", exclude={"evidence"})
        payload["evidence_ids"] = [
            add_location(item, item.basis, item.producer) for item in path.evidence
        ]
        risk_paths.append(payload)

    issues = []
    for issue in hsda.issues:
        payload = issue.model_dump(mode="json", exclude={"location"})
        payload["evidence_ids"] = [
            add_location(issue.location, "UNKNOWN", f"HSDA:{issue.analyzer}")
        ]
        issues.append(payload)

    return AnalysisPackage(
        update_id=update_id,
        skill_metadata=skill_metadata,
        old_function_summary=old_function_summary,
        new_function_summary=new_function_summary,
        structure_diff=[change_payload(item) for item in hsda.structure_changes],
        semantic_diff=[change_payload(item) for item in hsda.semantic_changes],
        code_behavior_diff=[
            change_payload(item) for item in hsda.code_behavior_changes
        ],
        permission_diff=[change_payload(item) for item in hsda.permission_changes],
        reference_diff=[change_payload(item) for item in hsda.reference_changes],
        unknown_diff=[change_payload(item) for item in hsda.unknown_changes],
        old_behavior_graph=graph_payload(graph.old_graph),
        new_behavior_graph=graph_payload(graph.new_graph),
        new_risk_paths=risk_paths,
        evidence_catalog=list(catalog.values()),
        analysis_issues=issues,
    )
