from __future__ import annotations

import json
import subprocess

import pytest
from conftest import FIXTURES

from skillupdate.sandbox import DockerSandboxRunner


def attestation_line():
    payload = {
        "uid": 65532,
        "gid": 65532,
        "effective_capabilities_hex": "0000000000000000",
        "no_new_privileges": True,
        "seccomp_mode": 2,
        "apparmor_profile": "docker-default (enforce)",
        "network_interfaces": ["lo"],
        "environment_names": ["FAKE_API_TOKEN", "HOME", "PATH"],
        "forbidden_environment_names": [],
        "root_write_blocked": True,
        "tmpfs_write_succeeded": True,
        "fixture_source_type": "CONTROLLED_MOCK",
        "harness_version": "p14-mock-harness-v1",
    }
    return "SKILLUPDATE_ATTESTATION=" + json.dumps(payload)


def test_docker_command_enforces_isolation(policy, context):
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, attestation_line() + "\n", "")

    runner = DockerSandboxRunner(
        policy,
        approved_fixture_root=FIXTURES,
        command_runner=fake_run,
    )
    result = runner.run(
        FIXTURES / "old", "OLD", context, ["FILE_ACCESS", "TOOL_INVOCATION"]
    )
    command = commands[0]
    assert result.state == "COMPLETED"
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--pull") + 1] == "never"
    assert command[command.index("--entrypoint") + 1] == "python"
    assert command[command.index("--ipc") + 1] == "none"
    assert command[command.index("--cgroupns") + 1] == "private"
    assert command[command.index("--user") + 1] == "65532:65532"
    assert "--read-only" in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert "no-new-privileges=true" in command
    assert command[command.index("--pids-limit") + 1] == "32"
    assert command[command.index("--memory") + 1] == "128m"
    assert command[command.index("--cpus") + 1] == "0.5"
    assert command[command.index("--tmpfs") + 1].startswith("/tmp:rw,noexec,nosuid,nodev")
    mounts = [command[index + 1] for index, value in enumerate(command) if value == "--mount"]
    assert len(mounts) == 2 and all(item.endswith("readonly") for item in mounts)
    assert all(".skilldetonate-secrets" not in item for item in command)


def test_runner_rejects_fixture_outside_approved_root(policy, context, tmp_path):
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "source_type": "CONTROLLED_MOCK",
                "fixture_id": "outside",
            }
        )
    )
    (tmp_path / "scenario.json").write_text(
        json.dumps({"schema_version": "1.0", "actions": []})
    )
    runner = DockerSandboxRunner(policy, approved_fixture_root=FIXTURES)
    with pytest.raises(ValueError, match="outside"):
        runner.run(tmp_path, "NEW", context, ["FILE_ACCESS"])


def test_runtime_attestation_rejects_root(policy, context):
    payload = json.loads(attestation_line().split("=", 1)[1])
    payload["uid"] = 0

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            "SKILLUPDATE_ATTESTATION=" + json.dumps(payload) + "\n",
            "",
        )

    runner = DockerSandboxRunner(
        policy, approved_fixture_root=FIXTURES, command_runner=fake_run
    )
    result = runner.run(FIXTURES / "old", "OLD", context, ["FILE_ACCESS"])
    assert result.state == "FAILED"
    assert result.attestation is None
    assert any("invalid harness evidence" in issue for issue in result.issues)


def test_runner_rejects_unreviewed_image(policy):
    unreviewed = policy.model_copy(update={"image_id": "sha256:" + "1" * 64})
    with pytest.raises(ValueError, match="allowlist"):
        DockerSandboxRunner(unreviewed, approved_fixture_root=FIXTURES)
