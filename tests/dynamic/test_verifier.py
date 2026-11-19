from __future__ import annotations

import json
import shutil

from conftest import FIXTURES

from skillupdate.dynamic_verification import (
    ExecutionPermit,
    RiskGuidedDynamicVerifier,
    RiskGuidedPlanner,
)


class NoRun:
    def run(self, *args, **kwargs):
        raise AssertionError("LOW risk must not start a container")


def test_low_risk_never_calls_runner(low_graph, policy, context, fixture_digests):
    plan = RiskGuidedPlanner().plan(low_graph, policy, context, *fixture_digests)
    permit = ExecutionPermit(plan_sha256=plan.digest())
    result = RiskGuidedDynamicVerifier(NoRun()).verify(
        plan, permit, FIXTURES / "old", FIXTURES / "new"
    )
    assert result.state == "SKIPPED_LOW_RISK"
    assert result.old_run is None and result.new_run is None
    assert "does not prove" in result.limitations[0]


def test_permit_must_bind_exact_plan(low_graph, policy, context, fixture_digests):
    plan = RiskGuidedPlanner().plan(low_graph, policy, context, *fixture_digests)
    permit = ExecutionPermit(plan_sha256="0" * 64)
    try:
        RiskGuidedDynamicVerifier(NoRun()).verify(
            plan, permit, FIXTURES / "old", FIXTURES / "new"
        )
    except ValueError as exc:
        assert "exact plan" in str(exc)
    else:
        raise AssertionError("unbound execution permit must fail")


def test_fixture_content_must_match_permitted_plan(
    low_graph, policy, context, fixture_digests, tmp_path
):
    plan = RiskGuidedPlanner().plan(low_graph, policy, context, *fixture_digests)
    changed = tmp_path / "changed"
    shutil.copytree(FIXTURES / "new", changed)
    scenario = json.loads((changed / "scenario.json").read_text())
    scenario["actions"] = []
    (changed / "scenario.json").write_text(json.dumps(scenario))
    try:
        RiskGuidedDynamicVerifier(NoRun()).verify(
            plan,
            ExecutionPermit(plan_sha256=plan.digest()),
            FIXTURES / "old",
            changed,
        )
    except ValueError as exc:
        assert "new fixture content" in str(exc)
    else:
        raise AssertionError("changed fixture must invalidate the permit")
