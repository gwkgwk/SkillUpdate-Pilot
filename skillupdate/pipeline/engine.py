"""P17 orchestrator for HSDA, P12 graphs, P16 SCFG, LLM and controlled Mock."""
from __future__ import annotations
import hashlib
import json
import time
from pathlib import Path
from typing import Any

from skillupdate.behavior_graph import IncrementalBehaviorGraphAnalyzer
from skillupdate.capability import CapabilityAnalyzer
from skillupdate.decision import DecisionEngine
from skillupdate.dynamic_verification import ExecutionPermit, RiskGuidedDynamicVerifier
from skillupdate.dynamic_verification.models import DynamicVerificationResult
from skillupdate.dynamic_verification.planner import RiskGuidedPlanner
from skillupdate.hsda import HSDAAnalyzer
from skillupdate.llm import AnalysisPackage, AnalyzerResult, LLMSecurityAnalyzer, build_analysis_package
from skillupdate.llm.models import EvidenceCatalogItem, TokenUsage, unknown_assessment
from skillupdate.sandbox import controlled_fixture_sha256
from skillupdate.sandbox.models import ExecutionContext, SandboxPolicy
from skillupdate.scfg import SCFGBuilder, SCFGIncrementalAnalyzer, SCFGPathAnalyzer
from .models import PipelineDecision, SkillUpdatePipelineResult


def _evidence_id(item: Any) -> str:
    raw = item.model_dump(mode="json")
    encoded = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    return "ev-scfg-" + hashlib.sha256(encoded).hexdigest()[:20]


def _attach_scfg_paths(package: AnalysisPackage, paths) -> AnalysisPackage:
    catalog = {item.evidence_id: item for item in package.evidence_catalog}
    path_payloads = list(package.new_risk_paths)
    for path in paths.added_paths:
        evidence_ids = []
        for evidence in path.evidence:
            evidence_id = _evidence_id(evidence)
            evidence_ids.append(evidence_id)
            catalog[evidence_id] = EvidenceCatalogItem(
                evidence_id=evidence_id,
                snapshot=evidence.snapshot,
                file=evidence.file,
                start_line=evidence.start_line,
                end_line=evidence.end_line,
                excerpt=evidence.excerpt,
                basis="RULE_INFERENCE" if evidence.basis == "RULE_INFERENCE" else "STATIC_FACT",
                producer=evidence.producer or "P16_SCFG",
            )
        payload = path.model_dump(mode="json", exclude={"evidence"})
        payload["evidence_ids"] = sorted(set(evidence_ids))
        payload["path_source"] = "SCFG"
        path_payloads.append(payload)
    return package.model_copy(update={
        "new_risk_paths": path_payloads,
        "evidence_catalog": list(catalog.values()),
    })


def _unknown_llm(update_id: str) -> AnalyzerResult:
    return AnalyzerResult(
        update_id=update_id,
        requested_model="NOT_CONFIGURED",
        returned_model=None,
        parse_status="PROVIDER_ERROR",
        assessment=unknown_assessment("LLM analysis was not requested."),
        validation_errors=["LLM analysis was not requested."],
        usage=TokenUsage(input_tokens=0, output_tokens=0, total_tokens=0, estimated=True),
        latency_ms=0,
        attempts=0,
        audit_directory="",
    )


def _decision(update_id: str, base, paths, dynamic, coverage: str) -> PipelineDecision:
    added, removed = paths.added_paths, paths.removed_paths
    risks = sorted({risk for path in paths.new_paths for risk in path.risk_types} | set(base.risk_types))
    high_new = [path for path in added if path.severity in {"CRITICAL", "HIGH"}]
    if base.snapshot_status == "MALICIOUS":
        status, reason = "MALICIOUS", base.reason
    elif base.snapshot_status == "SUSPICIOUS" or added:
        status = "SUSPICIOUS"
        reason = "P16 SCFG identifies a newly introduced or modified candidate risk path; this is static inference, not proof of execution."
    elif coverage != "COMPLETE_FOR_GRAPH" or paths.coverage != "COMPLETE_FOR_GRAPH":
        status = "UNKNOWN"
        reason = "Graph or analysis coverage is incomplete; absence of a discovered path cannot establish safety."
    else:
        status, reason = base.snapshot_status, base.reason

    if added:
        impact = "RISK_INCREASED" if paths.old_paths else "NEW_RISK"
    elif removed:
        impact = "RISK_REDUCED" if paths.new_paths else "RISK_REMOVED"
    else:
        impact = base.update_impact

    dynamic_state = dynamic.state if dynamic else "NOT_REQUESTED"
    if dynamic and dynamic.state in {"FAILED", "PARTIAL"}:
        reason += " Dynamic verification was incomplete; missing observations do not imply safety."
    elif dynamic and any(item.state == "OBSERVED" for item in dynamic.observations):
        reason += " Controlled Mock verification observed new event(s), limited to the bounded harness."

    evidence = []
    for path in added:
        for item in path.evidence:
            evidence.append({
                "snapshot": item.snapshot, "file": item.file,
                "start_line": item.start_line, "end_line": item.end_line,
                "basis": item.basis, "producer": item.producer, "path_id": path.path_id,
            })
    unique = {json.dumps(item, sort_keys=True): item for item in evidence}
    basis = list(base.decision_basis)
    if added or removed:
        basis.append("SCFG_RULE_INFERENCE")
    if dynamic:
        basis.append("CONTROLLED_MOCK_OBSERVATION")
    return PipelineDecision(
        update_id=update_id, snapshot_status=status, update_impact=impact,
        reason=reason, risk_types=risks,
        new_scfg_path_ids=[item.path_id for item in added],
        removed_scfg_path_ids=[item.path_id for item in removed],
        evidence=[unique[key] for key in sorted(unique)],
        verification_required=(status != "BENIGN" or bool(high_new) or bool(dynamic and dynamic.state in {"FAILED", "PARTIAL"})),
        decision_basis=sorted(set(basis)), base_decision=base, dynamic_state=dynamic_state,
    )


class SkillUpdatePipeline:
    """Static-first pipeline. It never executes downloaded or real Skill code."""
    def __init__(
        self, *, hsda_analyzer=None, graph_analyzer=None, capability_analyzer=None,
        llm_analyzer: LLMSecurityAnalyzer | None = None,
        dynamic_verifier: RiskGuidedDynamicVerifier | None = None,
        scfg_builder=None, scfg_incremental=None, scfg_paths=None,
    ):
        self.hsda = hsda_analyzer or HSDAAnalyzer()
        self.behavior = graph_analyzer or IncrementalBehaviorGraphAnalyzer()
        self.capability = capability_analyzer or CapabilityAnalyzer()
        self.llm = llm_analyzer
        self.dynamic = dynamic_verifier
        self.scfg_builder = scfg_builder or SCFGBuilder()
        self.scfg_incremental = scfg_incremental or SCFGIncrementalAnalyzer()
        self.scfg_paths = scfg_paths or SCFGPathAnalyzer()

    def run(
        self, old_skill_directory: str | Path, new_skill_directory: str | Path, *,
        update_id: str, skill_metadata: dict[str, Any] | None = None,
        old_function_summary: str = "See OLD snapshot evidence and graph.",
        new_function_summary: str = "See NEW snapshot evidence and graph.",
        dynamic_context: ExecutionContext | None = None,
        sandbox_policy: SandboxPolicy | None = None,
        old_mock_fixture: str | Path | None = None,
        new_mock_fixture: str | Path | None = None,
        execution_permit: ExecutionPermit | None = None,
    ) -> SkillUpdatePipelineResult:
        started = time.perf_counter()
        old_path = Path(old_skill_directory).resolve(strict=True)
        new_path = Path(new_skill_directory).resolve(strict=True)
        hsda_report = self.hsda.analyze(old_path, new_path)
        graph_delta = self.behavior.compare(old_path, new_path)
        old_caps = self.capability.analyze(graph_delta.old_graph, hsda_report)
        new_caps = self.capability.analyze(graph_delta.new_graph, hsda_report)
        cap_delta = self.capability.compare(old_caps, new_caps)
        old_scfg = self.scfg_builder.build(graph_delta.old_graph, old_caps)
        new_scfg = self.scfg_builder.build(graph_delta.new_graph, new_caps)
        scfg_delta = self.scfg_incremental.compare(old_scfg, new_scfg, graph_delta)
        path_analysis = self.scfg_paths.analyze(scfg_delta)

        package = build_analysis_package(
            update_id=update_id, skill_metadata=skill_metadata or {},
            old_function_summary=old_function_summary,
            new_function_summary=new_function_summary, hsda=hsda_report, graph=graph_delta,
        )
        package = _attach_scfg_paths(package, path_analysis)
        llm_result = self.llm.analyze(package) if self.llm else _unknown_llm(update_id)
        base = DecisionEngine().decide(package, hsda_report, graph_delta, llm_result)

        dynamic_result: DynamicVerificationResult | None = None
        dynamic_requested = any((
            dynamic_context is not None, sandbox_policy is not None,
            old_mock_fixture is not None, new_mock_fixture is not None,
            execution_permit is not None,
        ))
        if dynamic_requested:
            if self.dynamic is None:
                raise ValueError("dynamic inputs supplied but no P14 verifier is configured")
            if not all((dynamic_context, sandbox_policy, old_mock_fixture, new_mock_fixture, execution_permit)):
                raise ValueError("dynamic verification requires context, policy, OLD/NEW CONTROLLED_MOCK fixtures, and plan-bound permit")
            plan = RiskGuidedPlanner().plan(
                graph_delta, sandbox_policy, dynamic_context,
                controlled_fixture_sha256(old_mock_fixture),
                controlled_fixture_sha256(new_mock_fixture),
            )
            if execution_permit.plan_sha256 != plan.digest():
                raise ValueError("execution permit does not match the generated plan")
            dynamic_result = self.dynamic.verify(
                plan, execution_permit, old_mock_fixture, new_mock_fixture
            )

        decision = _decision(update_id, base, path_analysis, dynamic_result, path_analysis.coverage)
        limitations = sorted(set([
            *cap_delta.limitations, *scfg_delta.limitations, *path_analysis.limitations,
            "No real Skill source is executed by this pipeline.",
            "LLM is optional and advisory; omitted LLM analysis is explicitly UNKNOWN.",
            "P14 execution is limited to explicitly supplied CONTROLLED_MOCK fixtures.",
            "Static path reachability is not proof of runtime data transmission or malicious intent.",
        ]))
        return SkillUpdatePipelineResult(
            update_id=update_id, hsda=hsda_report, behavior_graph=graph_delta,
            old_capabilities=old_caps, new_capabilities=new_caps,
            capability_delta=cap_delta, scfg_delta=scfg_delta,
            scfg_paths=path_analysis, llm_analysis=llm_result,
            dynamic_verification=dynamic_result, decision=decision,
            limitations=limitations, processing_time_ms=(time.perf_counter()-started)*1000,
        )
