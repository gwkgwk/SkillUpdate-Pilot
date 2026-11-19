from __future__ import annotations

from conftest import FakeProvider, assessment_for

from skillupdate.decision import DecisionEngine
from skillupdate.llm import AnalyzerConfig, LLMSecurityAnalyzer


def run_case(analysis, response, tmp_path):
    package, hsda, graph = analysis
    llm = LLMSecurityAnalyzer(
        FakeProvider([response]),
        AnalyzerConfig(model="fake-model", audit_root=tmp_path / "audit"),
    ).analyze(package)
    return DecisionEngine().decide(package, hsda, graph, llm)


def test_normal_update(benign_analysis, tmp_path):
    package, _, _ = benign_analysis
    result = run_case(
        benign_analysis,
        assessment_for(package, "BENIGN", "NO_NEW_RISK", confidence=0.99),
        tmp_path,
    )
    assert result.snapshot_status == "BENIGN"
    assert result.update_impact == "NO_NEW_RISK"
    assert result.verification_required is False
    assert result.evidence_locations


def test_malicious_update_requires_model_and_static_corroboration(
    malicious_analysis, tmp_path
):
    package, _, _ = malicious_analysis
    result = run_case(
        malicious_analysis,
        assessment_for(package, "MALICIOUS", "NEW_RISK"),
        tmp_path,
    )
    assert result.snapshot_status == "MALICIOUS"
    assert result.update_impact == "NEW_RISK"
    assert result.attack_paths
    assert "BEHAVIOR_GRAPH_RULE" in result.decision_basis
    assert "LLM_ADVISORY" in result.decision_basis


def test_confidence_alone_cannot_make_malicious(benign_analysis, tmp_path):
    package, _, _ = benign_analysis
    response = assessment_for(package, "BENIGN", "NO_NEW_RISK", confidence=1.0)
    response["snapshot_status"] = "MALICIOUS"
    result = run_case(benign_analysis, response, tmp_path)
    assert result.snapshot_status == "UNKNOWN"


def test_unrelated_grounded_citation_cannot_corroborate_malicious(
    malicious_analysis, tmp_path
):
    package, _, _ = malicious_analysis
    response = assessment_for(package, "MALICIOUS", "NEW_RISK")
    response["risk_types"] = ["UNRELATED_RISK"]
    response["attack_paths"] = []
    result = run_case(malicious_analysis, response, tmp_path)
    assert result.snapshot_status == "SUSPICIOUS"


def test_risk_escalation(escalation_analysis, tmp_path):
    package, _, _ = escalation_analysis
    result = run_case(
        escalation_analysis,
        assessment_for(package, "MALICIOUS", "RISK_INCREASED"),
        tmp_path,
    )
    assert result.snapshot_status == "MALICIOUS"
    assert result.update_impact == "RISK_INCREASED"


def test_risk_repair(repair_analysis, tmp_path):
    package, _, _ = repair_analysis
    result = run_case(
        repair_analysis,
        assessment_for(package, "BENIGN", "RISK_REMOVED"),
        tmp_path,
    )
    assert result.snapshot_status == "BENIGN"
    assert result.update_impact == "RISK_REMOVED"
    assert result.evidence_locations
    assert result.attack_paths
    assert result.historical_behaviors
