from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from skillupdate.behavior_graph import IncrementalBehaviorGraphAnalyzer
from skillupdate.sandbox import (
    ExecutionContext,
    ResourcePolicy,
    SandboxPolicy,
    controlled_fixture_sha256,
)

FIXTURES = ROOT / "tests" / "dynamic" / "fixtures"
IMAGE_ID = "sha256:b8fe4ce3655e95f7f22c2a87d8e03a2f1f0cedc488a8e9adf18cc5a18cfdf401"


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@pytest.fixture
def context():
    return ExecutionContext(
        task_id="p14-controlled-mock",
        task_description_sha256=digest("verify controlled behavior"),
        input_sha256=digest("identical synthetic input"),
        permission_profile_sha256=digest("network-none;mock-only"),
    )


@pytest.fixture
def policy():
    return SandboxPolicy(
        image_id=IMAGE_ID,
        resources=ResourcePolicy(
            cpus=0.5,
            memory_mb=128,
            pids_limit=32,
            wall_timeout_seconds=10,
            tmpfs_mb=16,
        ),
    )


@pytest.fixture
def fixture_digests():
    return (
        controlled_fixture_sha256(FIXTURES / "old"),
        controlled_fixture_sha256(FIXTURES / "new"),
    )


@pytest.fixture
def low_graph():
    root = ROOT / "data" / "controlled_skills" / "pilot-pdf-outline"
    return IncrementalBehaviorGraphAnalyzer().compare(
        root / "base", root / "benign_update"
    )


@pytest.fixture
def high_graph():
    root = ROOT / "data" / "controlled_skills" / "pilot-pdf-outline"
    return IncrementalBehaviorGraphAnalyzer().compare(
        root / "base", root / "malicious_update"
    )


@pytest.fixture
def medium_graph(high_graph):
    graph = high_graph.model_copy(deep=True)
    for path in graph.new_risk_paths:
        path.risk_types = ["CONFIGURED_ENDPOINT"]
    return graph
