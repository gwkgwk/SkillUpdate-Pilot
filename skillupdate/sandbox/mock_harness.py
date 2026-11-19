"""Fixed container harness for controlled Mock fixtures; never imports a Skill."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

HARNESS_VERSION = "p14-mock-harness-v1"
EVENT_PREFIX = "SKILLUPDATE_EVENT="
ATTESTATION_PREFIX = "SKILLUPDATE_ATTESTATION="
FORBIDDEN_ENV_MARKERS = (
    "OPENAI",
    "DEEPSEEK",
    "AWS_",
    "AZURE_",
    "GOOGLE_",
    "GITHUB_",
    "SSH_",
    "TOKEN",
    "KEY",
    "SECRET",
    "PASSWORD",
    "CREDENTIAL",
)
ALLOWED_ENV_NAMES = {
    "FAKE_API_TOKEN",
    "HOME",
    "HOSTNAME",
    "LANG",
    "PATH",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONHASHSEED",
}
ALLOWED_ACTIONS = {
    "file_access",
    "process_creation",
    "network_event",
    "tool_invocation",
    "mock_data_access",
    "mock_transfer",
}
ACTION_CATEGORY = {
    "file_access": "FILE_ACCESS",
    "process_creation": "PROCESS_CREATION",
    "network_event": "NETWORK_EVENT",
    "tool_invocation": "TOOL_INVOCATION",
    "mock_data_access": "MOCK_DATA_ACCESS",
}
TARGET_PREFIXES = {
    "file_access": "mockfs://",
    "process_creation": "mock-process://",
    "network_event": "mock://",
    "tool_invocation": "mock-tool://",
    "mock_data_access": "synthetic://",
    "mock_transfer": "mock://",
}


def stable_id(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()[:24]


def sanitize_environment() -> None:
    for name in list(os.environ):
        if name not in ALLOWED_ENV_NAMES:
            del os.environ[name]


def emit_event(
    side: str,
    ordinal: int,
    category: str,
    operation: str,
    target: str,
    detail: dict[str, Any] | None = None,
) -> None:
    payload = {
        "event_id": f"dyn-{stable_id(side, str(ordinal), category, operation, target)}",
        "side": side,
        "category": category,
        "operation": operation,
        "target": target,
        "detail": detail or {},
        "evidence_source": "CONTAINER_MOCK_HARNESS",
    }
    print(EVENT_PREFIX + json.dumps(payload, sort_keys=True), flush=True)


def load_fixture() -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = json.loads(Path("/fixture/manifest.json").read_text(encoding="utf-8"))
    scenario = json.loads(Path("/fixture/scenario.json").read_text(encoding="utf-8"))
    if set(manifest) != {"schema_version", "source_type", "fixture_id"}:
        raise ValueError("invalid controlled fixture manifest fields")
    if manifest["schema_version"] != "1.0" or manifest["source_type"] != "CONTROLLED_MOCK":
        raise ValueError("only CONTROLLED_MOCK fixtures are accepted")
    if set(scenario) != {"schema_version", "actions"} or scenario["schema_version"] != "1.0":
        raise ValueError("invalid scenario schema")
    if not isinstance(scenario["actions"], list) or len(scenario["actions"]) > 64:
        raise ValueError("invalid action count")
    return manifest, scenario


def validate_action(action: Any) -> tuple[str, str]:
    if not isinstance(action, dict) or set(action) != {"action", "target"}:
        raise ValueError("mock action must contain exactly action and target")
    action_type = action["action"]
    target = action["target"]
    if action_type not in ALLOWED_ACTIONS or not isinstance(target, str):
        raise ValueError("unsupported mock action")
    if len(target) > 256 or not target.startswith(TARGET_PREFIXES[action_type]):
        raise ValueError("mock target violates the required synthetic scheme")
    return action_type, target


def process_security_status() -> tuple[str, bool, int]:
    values = {}
    for line in Path("/proc/self/status").read_text().splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            values[key] = value.strip()
    if not {"CapEff", "NoNewPrivs", "Seccomp"} <= set(values):
        raise RuntimeError("process security status is incomplete")
    return values["CapEff"], values["NoNewPrivs"] == "1", int(values["Seccomp"])


def attest(manifest: dict[str, Any]) -> None:
    capabilities, no_new_privileges, seccomp_mode = process_security_status()
    root_write_blocked = False
    try:
        Path("/rootfs-write-probe").write_text("blocked", encoding="utf-8")
    except OSError:
        root_write_blocked = True
    tmp_path = Path("/tmp/work/tmpfs-probe")
    tmp_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path.write_text("synthetic", encoding="utf-8")
    tmpfs_write_succeeded = tmp_path.read_text(encoding="utf-8") == "synthetic"
    env_names = sorted(os.environ)
    forbidden = sorted(
        name
        for name in env_names
        if name != "FAKE_API_TOKEN"
        and any(marker in name.upper() for marker in FORBIDDEN_ENV_MARKERS)
    )
    payload = {
        "uid": os.getuid(),
        "gid": os.getgid(),
        "effective_capabilities_hex": capabilities,
        "no_new_privileges": no_new_privileges,
        "seccomp_mode": seccomp_mode,
        "apparmor_profile": Path("/proc/self/attr/current").read_text().strip(),
        "network_interfaces": sorted(item.name for item in Path("/sys/class/net").iterdir()),
        "environment_names": env_names,
        "forbidden_environment_names": forbidden,
        "root_write_blocked": root_write_blocked,
        "tmpfs_write_succeeded": tmpfs_write_succeeded,
        "fixture_source_type": manifest["source_type"],
        "harness_version": HARNESS_VERSION,
    }
    print(ATTESTATION_PREFIX + json.dumps(payload, sort_keys=True), flush=True)


def execute(side: str, scenario: dict[str, Any], allowed_events: set[str]) -> None:
    fake_token = os.environ.get("FAKE_API_TOKEN", "")
    if not fake_token.startswith("FAKE_"):
        raise ValueError("synthetic credential is missing")
    for ordinal, raw_action in enumerate(scenario["actions"]):
        action, target = validate_action(raw_action)
        if action != "mock_transfer" and ACTION_CATEGORY[action] not in allowed_events:
            continue
        if action == "file_access":
            synthetic = Path("/tmp/work/synthetic-input.txt")
            synthetic.write_text("controlled-input", encoding="utf-8")
            synthetic.read_text(encoding="utf-8")
            emit_event(side, ordinal, "FILE_ACCESS", "READ", target, {"backend": "tmpfs"})
        elif action == "process_creation":
            emit_event(
                side,
                ordinal,
                "PROCESS_CREATION",
                "MOCK_REQUEST_ONLY",
                target,
                {"spawned": False},
            )
        elif action == "network_event":
            emit_event(
                side,
                ordinal,
                "NETWORK_EVENT",
                "MOCK_ENDPOINT_ONLY",
                target,
                {"socket_opened": False},
            )
        elif action == "tool_invocation":
            emit_event(side, ordinal, "TOOL_INVOCATION", "MOCK_TOOL", target)
        elif action == "mock_data_access":
            emit_event(
                side,
                ordinal,
                "MOCK_DATA_ACCESS",
                "READ_SYNTHETIC",
                target,
                {"value_sha256": hashlib.sha256(fake_token.encode()).hexdigest()},
            )
        elif action == "mock_transfer":
            if "NETWORK_EVENT" in allowed_events:
                emit_event(
                    side,
                    ordinal,
                    "NETWORK_EVENT",
                    "MOCK_ENDPOINT_ONLY",
                    target,
                    {"socket_opened": False},
                )
            if "MOCK_TRANSFER_EVENT" in allowed_events:
                emit_event(
                    side,
                    ordinal + 10_000,
                    "MOCK_TRANSFER_EVENT",
                    "IN_MEMORY_STAGE",
                    target,
                    {"transmitted": False},
                )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--side", choices=("OLD", "NEW"), required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--input-sha256", required=True)
    parser.add_argument("--task-description-sha256", required=True)
    parser.add_argument("--permission-profile-sha256", required=True)
    parser.add_argument(
        "--allow-event",
        action="append",
        choices=(
            "FILE_ACCESS",
            "PROCESS_CREATION",
            "NETWORK_EVENT",
            "TOOL_INVOCATION",
            "MOCK_DATA_ACCESS",
            "MOCK_TRANSFER_EVENT",
        ),
        required=True,
    )
    args = parser.parse_args()
    sanitize_environment()
    for value in (
        args.input_sha256,
        args.task_description_sha256,
        args.permission_profile_sha256,
    ):
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError("context digest is invalid")
    manifest, scenario = load_fixture()
    attest(manifest)
    execute(args.side, scenario, set(args.allow_event))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
