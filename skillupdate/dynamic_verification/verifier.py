"""Execute matched old/new Mock runs and compute evidence-preserving deltas."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from skillupdate.sandbox import (
    DockerSandboxRunner,
    MockEvent,
    controlled_fixture_sha256,
)

from .models import (
    BehaviorDelta,
    DynamicObservation,
    DynamicVerificationResult,
    ExecutionPermit,
    VerificationPlan,
)


def _event_key(event: MockEvent) -> tuple[str, str, str, str]:
    return (
        event.category,
        event.operation,
        event.target,
        json.dumps(event.detail, sort_keys=True, separators=(",", ":")),
    )


class RiskGuidedDynamicVerifier:
    def __init__(self, runner: DockerSandboxRunner) -> None:
        self.runner = runner

    def verify(
        self,
        plan: VerificationPlan,
        permit: ExecutionPermit,
        old_fixture: str | Path,
        new_fixture: str | Path,
    ) -> DynamicVerificationResult:
        if permit.plan_sha256 != plan.digest():
            raise ValueError("execution permit does not bind the exact plan")
        if controlled_fixture_sha256(old_fixture) != plan.old_fixture_sha256:
            raise ValueError("old fixture content does not match the authorized plan")
        if controlled_fixture_sha256(new_fixture) != plan.new_fixture_sha256:
            raise ValueError("new fixture content does not match the authorized plan")
        limitation = (
            "NOT_OBSERVED means the bounded Mock test did not produce a new event; "
            "it does not prove the Skill safe."
        )
        if not plan.execution_required:
            return DynamicVerificationResult(
                plan_id=plan.plan_id,
                risk_level=plan.risk_level,
                state="SKIPPED_LOW_RISK",
                old_run=None,
                new_run=None,
                behavior_delta=[],
                observations=[],
                evidence_events=[],
                limitations=[limitation, "LOW risk policy prohibited container startup."],
            )
        categories = list(plan.selected_event_categories)
        old_run = self.runner.run(old_fixture, "OLD", plan.context, categories)
        new_run = self.runner.run(new_fixture, "NEW", plan.context, categories)
        if old_run.state != "COMPLETED" or new_run.state != "COMPLETED":
            return DynamicVerificationResult(
                plan_id=plan.plan_id,
                risk_level=plan.risk_level,
                state="FAILED",
                old_run=old_run,
                new_run=new_run,
                behavior_delta=[],
                observations=[
                    DynamicObservation(
                        category=category,
                        state="UNKNOWN",
                        delta_event_ids=[],
                        explanation="At least one matched container run failed.",
                    )
                    for category in categories
                ],
                evidence_events=[*old_run.events, *new_run.events],
                limitations=[limitation, "Failed runs cannot support absence claims."],
            )
        old_by_key: dict[tuple[str, str, str, str], list[MockEvent]] = defaultdict(list)
        new_by_key: dict[tuple[str, str, str, str], list[MockEvent]] = defaultdict(list)
        for event in old_run.events:
            old_by_key[_event_key(event)].append(event)
        for event in new_run.events:
            new_by_key[_event_key(event)].append(event)
        delta: list[BehaviorDelta] = []
        for key in sorted(set(old_by_key) | set(new_by_key)):
            old_events = old_by_key[key]
            new_events = new_by_key[key]
            change = (
                "ADDED"
                if len(new_events) > len(old_events)
                else "REMOVED"
                if len(new_events) < len(old_events)
                else "UNCHANGED"
            )
            delta.append(
                BehaviorDelta(
                    category=key[0],
                    operation=key[1],
                    target=key[2],
                    old_count=len(old_events),
                    new_count=len(new_events),
                    change=change,
                    old_event_ids=[event.event_id for event in old_events],
                    new_event_ids=[event.event_id for event in new_events],
                )
            )
        observations = []
        for category in categories:
            added_ids = [
                event_id
                for item in delta
                if item.category == category and item.change == "ADDED"
                for event_id in item.new_event_ids
            ]
            observations.append(
                DynamicObservation(
                    category=category,
                    state="OBSERVED" if added_ids else "NOT_OBSERVED",
                    delta_event_ids=added_ids,
                    explanation=(
                        "New-version-only Mock events were observed."
                        if added_ids
                        else "No new event was observed in the bounded matched test."
                    ),
                )
            )
        return DynamicVerificationResult(
            plan_id=plan.plan_id,
            risk_level=plan.risk_level,
            state="COMPLETED",
            old_run=old_run,
            new_run=new_run,
            behavior_delta=delta,
            observations=observations,
            evidence_events=[*old_run.events, *new_run.events],
            limitations=[limitation, "All events come from a controlled Mock harness."],
        )
