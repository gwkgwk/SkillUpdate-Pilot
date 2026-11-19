from __future__ import annotations

import os

import pytest
from conftest import FIXTURES

from skillupdate.dynamic_verification import (
    ExecutionPermit,
    RiskGuidedDynamicVerifier,
    RiskGuidedPlanner,
)
from skillupdate.sandbox import DockerSandboxRunner


@pytest.mark.skipif(
    os.environ.get("SKILLUPDATE_RUN_DOCKER_TESTS") != "1",
    reason="real Docker integration requires explicit P14 opt-in",
)
def test_real_matched_docker_verification(
    high_graph, policy, context, fixture_digests
):
    plan = RiskGuidedPlanner().plan(high_graph, policy, context, *fixture_digests)
    runner = DockerSandboxRunner(policy, approved_fixture_root=FIXTURES)
    result = RiskGuidedDynamicVerifier(runner).verify(
        plan,
        ExecutionPermit(plan_sha256=plan.digest()),
        FIXTURES / "old",
        FIXTURES / "new",
    )
    assert result.state == "COMPLETED"
    assert result.old_run and result.new_run
    assert result.old_run.attestation and result.new_run.attestation
    assert result.old_run.attestation.uid == 65532
    assert result.new_run.attestation.network_interfaces == ["lo"]
    assert result.new_run.attestation.no_new_privileges is True
    assert result.new_run.attestation.seccomp_mode == 2
    assert "docker-default" in result.new_run.attestation.apparmor_profile
    assert set(result.new_run.attestation.environment_names) <= {
        "FAKE_API_TOKEN",
        "HOME",
        "HOSTNAME",
        "LANG",
        "PATH",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONHASHSEED",
    }
    observed = {
        item.category for item in result.observations if item.state == "OBSERVED"
    }
    not_observed = {
        item.category
        for item in result.observations
        if item.state == "NOT_OBSERVED"
    }
    assert observed == {
        "MOCK_DATA_ACCESS",
        "MOCK_TRANSFER_EVENT",
        "NETWORK_EVENT",
        "PROCESS_CREATION",
    }
    assert not_observed == {"FILE_ACCESS", "TOOL_INVOCATION"}
    assert all(
        event.detail.get("spawned") is not True
        and event.detail.get("socket_opened") is not True
        and event.detail.get("transmitted") is not True
        for event in result.evidence_events
    )
