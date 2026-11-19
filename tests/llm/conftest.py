from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from skillupdate.behavior_graph import IncrementalBehaviorGraphAnalyzer
from skillupdate.hsda import HSDAAnalyzer
from skillupdate.llm import (
    ProviderError,
    ProviderResponse,
    TokenUsage,
    build_analysis_package,
)

CONTROLLED = ROOT / "data" / "controlled_skills" / "pilot-pdf-outline"


class FakeProvider:
    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def complete(self, **kwargs: Any) -> ProviderResponse:
        self.calls.append(kwargs)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        text = response if isinstance(response, str) else json.dumps(response)
        return ProviderResponse(
            text=text,
            model="fake-model-v1",
            request_id="fake-request",
            usage=TokenUsage(
                input_tokens=100,
                output_tokens=50,
                total_tokens=150,
            ),
            raw={"fixture": True},
        )


def make_analysis(old: Path, new: Path, update_id: str = "update-test"):
    hsda = HSDAAnalyzer().analyze(old, new)
    graph = IncrementalBehaviorGraphAnalyzer().compare(old, new)
    package = build_analysis_package(
        update_id,
        {"skill_id": "pilot-pdf-outline", "source_type": "CONTROLLED"},
        "PDF outline workflow",
        "Updated PDF outline workflow",
        hsda,
        graph,
    )
    return package, hsda, graph


def assessment_for(package, status: str, impact: str, *, confidence: float = 0.9):
    if status in {"SUSPICIOUS", "MALICIOUS"}:
        path = package.new_risk_paths[0]
        evidence_id = path["evidence_ids"][0]
        evidence = next(
            item for item in package.evidence_catalog if item.evidence_id == evidence_id
        )
        return {
            "snapshot_status": status,
            "update_impact": impact,
            "risk_types": path["risk_types"],
            "new_behaviors": [
                {"behavior": path["explanation"], "evidence_ids": [evidence_id]}
            ],
            "historical_behaviors": [],
            "evidence_files": [evidence.file],
            "evidence_locations": [
                {
                    "evidence_id": evidence_id,
                    "file": evidence.file,
                    "start_line": evidence.start_line,
                    "end_line": evidence.end_line,
                }
            ],
            "attack_paths": [path["path_id"]],
            "reason": "Grounded controlled-fixture risk path.",
            "confidence": confidence,
            "verification_required": True,
        }
    return {
        "snapshot_status": status,
        "update_impact": impact,
        "risk_types": [],
        "new_behaviors": [],
        "historical_behaviors": [],
        "evidence_files": [],
        "evidence_locations": [],
        "attack_paths": [],
        "reason": "No new risk is supported by the supplied evidence.",
        "confidence": confidence,
        "verification_required": status != "BENIGN",
    }


@pytest.fixture
def benign_analysis():
    return make_analysis(CONTROLLED / "base", CONTROLLED / "benign_update", "benign")


@pytest.fixture
def malicious_analysis():
    return make_analysis(
        CONTROLLED / "base", CONTROLLED / "malicious_update", "malicious"
    )


@pytest.fixture
def escalation_analysis(tmp_path: Path):
    old = tmp_path / "old"
    new = tmp_path / "new"
    shutil.copytree(CONTROLLED / "malicious_update", old)
    shutil.copytree(old, new)
    with (new / "scripts" / "main.py").open("a", encoding="utf-8") as handle:
        handle.write(
            "\n\nfrom unittest.mock import Mock\n"
            "\n\ndef controlled_process(audit_log):\n"
            "    mock_process = Mock()\n"
            "    result = mock_process.spawn('synthetic-command')\n"
            "    audit_log.append('mock-only')\n"
            "    return result\n"
        )
    return make_analysis(old, new, "escalation")


@pytest.fixture
def repair_analysis():
    return make_analysis(
        CONTROLLED / "malicious_update", CONTROLLED / "base", "repair"
    )


__all__ = [
    "CONTROLLED",
    "FakeProvider",
    "ProviderError",
    "assessment_for",
    "make_analysis",
]
