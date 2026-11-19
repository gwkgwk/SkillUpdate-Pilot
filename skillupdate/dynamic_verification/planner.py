"""Select dynamic event families from incremental static risk paths."""

from __future__ import annotations

import hashlib
import json

from skillupdate.behavior_graph.models import BehavioralGraphDelta
from skillupdate.sandbox.models import ExecutionContext, SandboxPolicy

from .models import VerificationPlan

ALL_CATEGORIES = [
    "FILE_ACCESS",
    "PROCESS_CREATION",
    "NETWORK_EVENT",
    "TOOL_INVOCATION",
    "MOCK_DATA_ACCESS",
    "MOCK_TRANSFER_EVENT",
]
HIGH_RISKS = {
    "SENSITIVE_DATA_ACCESS",
    "DATA_TRANSMISSION_INTENT",
    "DATA_TRANSMISSION",
    "PROCESS_EXECUTION",
    "SENSITIVE_DATA",
}


def _stable_id(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:24]


class RiskGuidedPlanner:
    def plan(
        self,
        graph: BehavioralGraphDelta,
        sandbox_policy: SandboxPolicy,
        context: ExecutionContext,
        old_fixture_sha256: str,
        new_fixture_sha256: str,
    ) -> VerificationPlan:
        paths = graph.new_risk_paths
        risks = sorted({risk for path in paths for risk in path.risk_types})
        if not paths:
            level = "LOW"
            depth = "SKIP"
            categories: list[str] = []
            rationale = "No new semantic risk path; dynamic execution is skipped."
        elif set(risks) & HIGH_RISKS:
            level = "HIGH"
            depth = "DEEP"
            categories = ALL_CATEGORIES
            rationale = (
                "Sensitive-data, transmission, or process risk requires all bounded "
                "Mock event families."
            )
        else:
            level = "MEDIUM"
            depth = "DIRECTED"
            selected: set[str] = {"TOOL_INVOCATION"}
            joined = " ".join(risks)
            if "FILE" in joined:
                selected.add("FILE_ACCESS")
            if "ENDPOINT" in joined or "NETWORK" in joined:
                selected.update({"NETWORK_EVENT", "MOCK_TRANSFER_EVENT"})
            if "DATA" in joined:
                selected.add("MOCK_DATA_ACCESS")
            if "PROCESS" in joined or "COMMAND" in joined:
                selected.add("PROCESS_CREATION")
            categories = sorted(selected)
            rationale = "New static risk paths receive a directed Mock verification."
        plan_payload = {
            "paths": [path.path_id for path in paths],
            "risks": risks,
            "level": level,
            "categories": categories,
            "context": context.model_dump(mode="json"),
            "policy": sandbox_policy.model_dump(mode="json"),
            "old_fixture_sha256": old_fixture_sha256,
            "new_fixture_sha256": new_fixture_sha256,
        }
        return VerificationPlan(
            plan_id=f"vp-{_stable_id(plan_payload)}",
            risk_level=level,
            depth=depth,
            execution_required=level != "LOW",
            selected_path_ids=sorted(path.path_id for path in paths),
            selected_risk_types=risks,
            selected_event_categories=categories,
            old_fixture_sha256=old_fixture_sha256,
            new_fixture_sha256=new_fixture_sha256,
            context=context,
            sandbox_policy=sandbox_policy,
            rationale=rationale,
        )
