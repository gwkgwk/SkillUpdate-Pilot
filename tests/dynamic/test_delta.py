from __future__ import annotations

import hashlib
import json

from conftest import FIXTURES

from skillupdate.dynamic_verification import (
    ExecutionPermit,
    RiskGuidedDynamicVerifier,
    RiskGuidedPlanner,
)
from skillupdate.sandbox import ContainerRunResult, MockEvent, RuntimeAttestation


def run_result(side, events):
    attestation = RuntimeAttestation(
        uid=65532,
        gid=65532,
        effective_capabilities_hex="0000000000000000",
        no_new_privileges=True,
        seccomp_mode=2,
        apparmor_profile="docker-default (enforce)",
        network_interfaces=["lo"],
        environment_names=["FAKE_API_TOKEN"],
        forbidden_environment_names=[],
        root_write_blocked=True,
        tmpfs_write_succeeded=True,
        fixture_source_type="CONTROLLED_MOCK",
        harness_version="p14-mock-harness-v1",
    )
    return ContainerRunResult(
        side=side,
        state="COMPLETED",
        exit_code=0,
        events=events,
        attestation=attestation,
        stdout_sha256="0" * 64,
        stderr_sha256="0" * 64,
        command_sha256="0" * 64,
        command=["docker", "run", "<controlled>"],
        duration_ms=1,
    )


def event(side, category, operation, target, detail=None):
    payload = json.dumps([category, operation, target, detail or {}], sort_keys=True)
    return MockEvent(
        event_id="dyn-" + hashlib.sha256((side + payload).encode()).hexdigest()[:24],
        side=side,
        category=category,
        operation=operation,
        target=target,
        detail=detail or {},
    )


class MatchedRunner:
    def run(self, fixture, side, context, categories):
        common = event(side, "FILE_ACCESS", "READ", "mockfs://workspace/input.txt")
        events = [common]
        if side == "NEW":
            events.append(
                event(
                    side,
                    "NETWORK_EVENT",
                    "MOCK_ENDPOINT_ONLY",
                    "mock://collector.invalid/test",
                    {"socket_opened": False},
                )
            )
        return run_result(side, events)


def test_multiset_delta_distinguishes_observed_and_not_observed(
    high_graph, policy, context, fixture_digests
):
    plan = RiskGuidedPlanner().plan(high_graph, policy, context, *fixture_digests)
    result = RiskGuidedDynamicVerifier(MatchedRunner()).verify(
        plan,
        ExecutionPermit(plan_sha256=plan.digest()),
        FIXTURES / "old",
        FIXTURES / "new",
    )
    states = {item.category: item.state for item in result.observations}
    assert result.state == "COMPLETED"
    assert states["NETWORK_EVENT"] == "OBSERVED"
    assert states["FILE_ACCESS"] == "NOT_OBSERVED"
    assert any("does not prove" in item for item in result.limitations)
    network_delta = next(
        item for item in result.behavior_delta if item.category == "NETWORK_EVENT"
    )
    assert network_delta.change == "ADDED"
    assert network_delta.old_count == 0 and network_delta.new_count == 1
