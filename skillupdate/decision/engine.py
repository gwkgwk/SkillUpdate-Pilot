"""Versioned evidence fusion; confidence is never a classification rule."""

from __future__ import annotations

from skillupdate.behavior_graph.models import BehavioralGraphDelta, RiskPath
from skillupdate.behavior_graph.paths import find_new_risk_paths
from skillupdate.hsda.models import HSDAReport
from skillupdate.llm.models import (
    AnalysisPackage,
    AnalyzerResult,
    BehaviorStatement,
    EvidenceLocation,
)

from .models import DecisionOutcome

POLICY_VERSION = "skillupdate-decision-v1"


def _all_paths(graph) -> list[RiskPath]:
    return find_new_risk_paths(
        graph,
        {node.node_id for node in graph.nodes},
        {edge.edge_id for edge in graph.edges},
    )


class DecisionEngine:
    """Fuse static facts, semantic graph paths, coverage, and LLM advice."""

    def decide(
        self,
        package: AnalysisPackage,
        hsda: HSDAReport,
        graph: BehavioralGraphDelta,
        llm: AnalyzerResult,
    ) -> DecisionOutcome:
        if package.update_id != llm.update_id:
            raise ValueError("analysis package and LLM result update IDs differ")

        old_paths = _all_paths(graph.old_graph)
        new_paths = _all_paths(graph.new_graph)
        old_path_ids = {path.path_id for path in old_paths}
        new_path_ids = {path.path_id for path in new_paths}
        added_paths = [path for path in new_paths if path.path_id not in old_path_ids]
        removed_paths = [path for path in old_paths if path.path_id not in new_path_ids]

        # HSDA security relevance is intentionally recall-oriented (for example,
        # a changed safety string is relevant). It corroborates a decision but
        # does not, by itself, establish a current risk behavior. Risk state and
        # transitions therefore use semantic paths rather than keyword sets.
        old_risks = {risk for path in old_paths for risk in path.risk_types}
        new_risks = {risk for path in new_paths for risk in path.risk_types}
        added_risks = new_risks - old_risks
        removed_risks = old_risks - new_risks
        coverage_limited = bool(hsda.issues or hsda.unknown_changes)

        if added_paths or added_risks:
            impact = "RISK_INCREASED" if old_risks else "NEW_RISK"
        elif removed_paths or removed_risks:
            impact = "RISK_REDUCED" if new_risks else "RISK_REMOVED"
        elif coverage_limited or llm.parse_status != "VALID":
            impact = "UNKNOWN"
        else:
            impact = "NO_NEW_RISK"

        advisory = llm.assessment
        grounded_model_risk = bool(
            advisory.evidence_locations
            and (
                advisory.risk_types
                or advisory.new_behaviors
                or advisory.snapshot_status in {"SUSPICIOUS", "MALICIOUS"}
            )
        )
        current_static_risk = bool(new_paths)
        corroborated_model_risk = grounded_model_risk and bool(
            set(advisory.risk_types) & new_risks
            or set(advisory.attack_paths) & new_path_ids
        )
        if (
            llm.parse_status == "VALID"
            and advisory.snapshot_status == "MALICIOUS"
            and corroborated_model_risk
            and current_static_risk
        ):
            status = "MALICIOUS"
        elif current_static_risk or (
            llm.parse_status == "VALID"
            and advisory.snapshot_status == "SUSPICIOUS"
            and grounded_model_risk
        ):
            status = "SUSPICIOUS"
        elif coverage_limited or llm.parse_status != "VALID":
            status = "UNKNOWN"
        elif advisory.snapshot_status == "BENIGN":
            status = "BENIGN"
        else:
            status = "UNKNOWN"

        catalog = {item.evidence_id: item for item in package.evidence_catalog}
        path_payloads = {
            item["path_id"]: item for item in package.new_risk_paths
        }
        selected_path_objects = [*added_paths, *removed_paths]
        selected_paths = [path.path_id for path in selected_path_objects]
        cited_ids = {
            item.evidence_id for item in advisory.evidence_locations
        }
        # Negative/update-repair decisions still need auditable source evidence.
        # Include every reviewed change location, then add evidence for both new
        # and removed semantic paths.
        for field in (
            package.structure_diff,
            package.semantic_diff,
            package.code_behavior_diff,
            package.permission_diff,
            package.reference_diff,
            package.unknown_diff,
        ):
            for change in field:
                cited_ids.update(change.get("evidence_ids", []))
        catalog_by_location = {
            (
                item.snapshot,
                item.file,
                item.start_line,
                item.end_line,
                item.excerpt,
                item.basis,
                item.producer,
            ): item.evidence_id
            for item in package.evidence_catalog
        }
        for path in selected_path_objects:
            cited_ids.update(path_payloads.get(path.path_id, {}).get("evidence_ids", []))
            for evidence in path.evidence:
                evidence_id = catalog_by_location.get(
                    (
                        evidence.snapshot,
                        evidence.file,
                        evidence.start_line,
                        evidence.end_line,
                        evidence.excerpt,
                        evidence.basis,
                        evidence.producer,
                    )
                )
                if evidence_id:
                    cited_ids.add(evidence_id)
        locations = [
            EvidenceLocation(
                evidence_id=evidence_id,
                file=catalog[evidence_id].file,
                start_line=catalog[evidence_id].start_line,
                end_line=catalog[evidence_id].end_line,
            )
            for evidence_id in sorted(cited_ids)
            if evidence_id in catalog
        ]

        new_behaviors = list(advisory.new_behaviors)
        known_behavior_text = {item.behavior for item in new_behaviors}
        for path in added_paths:
            payload = path_payloads.get(path.path_id, {})
            evidence_ids = payload.get("evidence_ids", [])
            if path.explanation not in known_behavior_text and evidence_ids:
                new_behaviors.append(
                    BehaviorStatement(
                        behavior=path.explanation,
                        evidence_ids=evidence_ids,
                    )
                )
        historical_behaviors = list(advisory.historical_behaviors)
        known_historical_text = {item.behavior for item in historical_behaviors}
        for path in removed_paths:
            evidence_ids = []
            for evidence in path.evidence:
                evidence_id = catalog_by_location.get(
                    (
                        evidence.snapshot,
                        evidence.file,
                        evidence.start_line,
                        evidence.end_line,
                        evidence.excerpt,
                        evidence.basis,
                        evidence.producer,
                    )
                )
                if evidence_id:
                    evidence_ids.append(evidence_id)
            if path.explanation not in known_historical_text and evidence_ids:
                historical_behaviors.append(
                    BehaviorStatement(
                        behavior=path.explanation,
                        evidence_ids=sorted(set(evidence_ids)),
                    )
                )

        basis: list[str] = []
        if any(
            (
                package.structure_diff,
                package.semantic_diff,
                package.code_behavior_diff,
                package.permission_diff,
                package.reference_diff,
                package.unknown_diff,
            )
        ):
            basis.append("HSDA_STATIC_FACT")
        if new_paths or old_paths:
            basis.append("BEHAVIOR_GRAPH_RULE")
        if llm.parse_status == "VALID":
            basis.append("LLM_ADVISORY")
        if coverage_limited or llm.parse_status != "VALID":
            basis.append("COVERAGE_LIMITATION")

        if status == "MALICIOUS":
            reason = (
                "Grounded LLM malicious assessment is corroborated by static "
                "security evidence or a semantic behavior path."
            )
        elif status == "SUSPICIOUS":
            reason = (
                "Static analysis identifies a risk-relevant behavior, but the "
                "available evidence does not establish observed malicious execution."
            )
        elif status == "BENIGN":
            reason = (
                "The evidence-constrained model reports BENIGN, static analysis "
                "finds no current risk path, and analyzed coverage has no known gap."
            )
        else:
            reason = (
                "Evidence, coverage, or model validation is insufficient for a "
                "supported snapshot classification."
            )

        return DecisionOutcome(
            update_id=package.update_id,
            snapshot_status=status,
            update_impact=impact,
            risk_types=sorted(new_risks | set(advisory.risk_types)),
            new_behaviors=new_behaviors,
            historical_behaviors=historical_behaviors,
            evidence_files=sorted({item.file for item in locations}),
            evidence_locations=locations,
            attack_paths=selected_paths,
            reason=reason,
            confidence=advisory.confidence if llm.parse_status == "VALID" else None,
            verification_required=(
                status != "BENIGN" or advisory.verification_required
            ),
            llm_advisory_status=advisory.snapshot_status,
            decision_basis=basis,
        )
