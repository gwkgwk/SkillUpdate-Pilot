"""Hardened Docker runner restricted to controlled P14 Mock fixtures."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from pydantic import ValidationError

from .models import (
    ContainerRunResult,
    ExecutionContext,
    MockEvent,
    RuntimeAttestation,
    SandboxPolicy,
)

EVENT_PREFIX = "SKILLUPDATE_EVENT="
ATTESTATION_PREFIX = "SKILLUPDATE_ATTESTATION="
P14_APPROVED_IMAGE_IDS = {
    "sha256:b8fe4ce3655e95f7f22c2a87d8e03a2f1f0cedc488a8e9adf18cc5a18cfdf401"
}


def controlled_fixture_sha256(fixture: str | Path) -> str:
    path = Path(fixture).resolve(strict=True)
    expected = ("manifest.json", "scenario.json")
    if not path.is_dir() or {item.name for item in path.iterdir()} != set(expected):
        raise ValueError("controlled fixture must contain exactly two files")
    digest = hashlib.sha256()
    for name in expected:
        item = path / name
        if item.is_symlink() or not item.is_file() or item.stat().st_size > 64 * 1024:
            raise ValueError("controlled fixture file is invalid")
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(item.read_bytes())
        digest.update(b"\0")
    manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("source_type") != "CONTROLLED_MOCK":
        raise ValueError("fixture source type is not CONTROLLED_MOCK")
    return digest.hexdigest()


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class DockerSandboxRunner:
    def __init__(
        self,
        policy: SandboxPolicy,
        *,
        approved_fixture_root: str | Path,
        harness_path: str | Path | None = None,
        command_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self.policy = policy
        self.approved_fixture_root = Path(approved_fixture_root).resolve(strict=True)
        self.harness_path = (
            Path(harness_path)
            if harness_path
            else Path(__file__).with_name("mock_harness.py")
        ).resolve(strict=True)
        self.command_runner = command_runner
        if self.policy.image_id not in P14_APPROVED_IMAGE_IDS:
            raise ValueError("sandbox image ID is not in the P14 reviewed allowlist")

    def _validate_fixture(self, fixture: str | Path) -> Path:
        path = Path(fixture).resolve(strict=True)
        if not path.is_dir() or not path.is_relative_to(self.approved_fixture_root):
            raise ValueError("fixture is outside the approved controlled root")
        relative = path.relative_to(self.approved_fixture_root)
        cursor = self.approved_fixture_root
        for part in relative.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise ValueError("fixture path must not contain symlinks")
        expected = {"manifest.json", "scenario.json"}
        files = {item.name for item in path.iterdir() if item.is_file()}
        if files != expected or any(item.is_symlink() for item in path.iterdir()):
            raise ValueError("controlled fixture must contain only manifest and scenario")
        if any((path / name).stat().st_size > 64 * 1024 for name in expected):
            raise ValueError("controlled fixture file exceeds 64 KiB")
        manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
        if manifest.get("source_type") != "CONTROLLED_MOCK":
            raise ValueError("public or unlabeled fixtures are prohibited")
        return path

    def _command(
        self,
        fixture: Path,
        side: str,
        context: ExecutionContext,
        cidfile: Path,
        allowed_categories: list[str],
    ) -> list[str]:
        resources = self.policy.resources
        command = [
            "docker",
            "run",
            "--rm",
            "--pull",
            "never",
            "--cidfile",
            str(cidfile),
            "--network",
            self.policy.network,
            "--ipc",
            "none",
            "--cgroupns",
            "private",
            "--user",
            self.policy.user,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--pids-limit",
            str(resources.pids_limit),
            "--memory",
            f"{resources.memory_mb}m",
            "--memory-swap",
            f"{resources.memory_mb}m",
            "--cpus",
            str(resources.cpus),
            "--ulimit",
            "nofile=64:64",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={resources.tmpfs_mb}m,mode=1777",
            "--workdir",
            "/tmp",
            "--hostname",
            "skillupdate-mock",
            "--env",
            "HOME=/tmp/home",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--env",
            "PYTHONHASHSEED=0",
            "--env",
            "FAKE_API_TOKEN=FAKE_DYNAMIC_TOKEN",
            "--mount",
            f"type=bind,src={self.harness_path},dst=/opt/skillupdate/harness.py,readonly",
            "--mount",
            f"type=bind,src={fixture},dst=/fixture,readonly",
            "--entrypoint",
            "python",
            self.policy.image_id,
            "-I",
            "-B",
            "/opt/skillupdate/harness.py",
            "--side",
            side,
            "--task-id",
            context.task_id,
            "--input-sha256",
            context.input_sha256,
            "--task-description-sha256",
            context.task_description_sha256,
            "--permission-profile-sha256",
            context.permission_profile_sha256,
        ]
        for category in sorted(set(allowed_categories)):
            command.extend(["--allow-event", category])
        return command

    def run(
        self,
        fixture: str | Path,
        side: str,
        context: ExecutionContext,
        allowed_categories: list[str],
    ) -> ContainerRunResult:
        if side not in {"OLD", "NEW"}:
            raise ValueError("side must be OLD or NEW")
        fixture_path = self._validate_fixture(fixture)
        allowed = {
            "FILE_ACCESS",
            "PROCESS_CREATION",
            "NETWORK_EVENT",
            "TOOL_INVOCATION",
            "MOCK_DATA_ACCESS",
            "MOCK_TRANSFER_EVENT",
        }
        if not allowed_categories or not set(allowed_categories) <= allowed:
            raise ValueError("allowed event categories are empty or invalid")
        started = time.perf_counter()
        with tempfile.TemporaryDirectory(prefix="skillupdate-p14-") as temporary:
            cidfile = Path(temporary) / "container.cid"
            command = self._command(
                fixture_path, side, context, cidfile, allowed_categories
            )
            stdout = ""
            stderr = ""
            exit_code: int | None = None
            state = "FAILED"
            issues: list[str] = []
            try:
                completed = self.command_runner(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=self.policy.resources.wall_timeout_seconds,
                )
                stdout = completed.stdout
                stderr = completed.stderr
                exit_code = completed.returncode
                state = "COMPLETED" if completed.returncode == 0 else "FAILED"
                if completed.returncode != 0:
                    issues.append(f"container exited with status {completed.returncode}")
            except subprocess.TimeoutExpired as exc:
                state = "TIMED_OUT"
                raw_stdout = exc.stdout or ""
                raw_stderr = exc.stderr or ""
                stdout = (
                    raw_stdout.decode(errors="replace")
                    if isinstance(raw_stdout, bytes)
                    else raw_stdout
                )
                stderr = (
                    raw_stderr.decode(errors="replace")
                    if isinstance(raw_stderr, bytes)
                    else raw_stderr
                )
                issues.append("container wall timeout exceeded")
                if cidfile.exists():
                    container_id = cidfile.read_text(encoding="utf-8").strip()
                    if re.fullmatch(r"[0-9a-f]{12,64}", container_id):
                        subprocess.run(
                            ["docker", "rm", "--force", container_id],
                            capture_output=True,
                            check=False,
                            timeout=5,
                        )

        events: list[MockEvent] = []
        attestation: RuntimeAttestation | None = None
        for line in stdout.splitlines():
            try:
                if line.startswith(EVENT_PREFIX):
                    events.append(MockEvent.model_validate_json(line[len(EVENT_PREFIX) :]))
                elif line.startswith(ATTESTATION_PREFIX):
                    attestation = RuntimeAttestation.model_validate_json(
                        line[len(ATTESTATION_PREFIX) :]
                    )
            except ValidationError as exc:
                issues.append(f"invalid harness evidence: {exc.title}")
                state = "FAILED"
        if state == "COMPLETED" and attestation is None:
            state = "FAILED"
            issues.append("runtime attestation missing")
        return ContainerRunResult(
            side=side,
            state=state,
            exit_code=exit_code,
            events=events,
            attestation=attestation,
            stdout_sha256=_digest(stdout),
            stderr_sha256=_digest(stderr),
            command_sha256=_digest(json.dumps(command, separators=(",", ":"))),
            command=command,
            duration_ms=(time.perf_counter() - started) * 1000,
            issues=issues,
        )
