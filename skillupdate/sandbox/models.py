"""Schemas for the P14 Docker sandbox and its evidence-bearing trace."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

EventCategory = Literal[
    "FILE_ACCESS",
    "PROCESS_CREATION",
    "NETWORK_EVENT",
    "TOOL_INVOCATION",
    "MOCK_DATA_ACCESS",
    "MOCK_TRANSFER_EVENT",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ResourcePolicy(StrictModel):
    cpus: float = Field(default=0.5, gt=0, le=2)
    memory_mb: int = Field(default=128, ge=64, le=512)
    pids_limit: int = Field(default=32, ge=8, le=64)
    wall_timeout_seconds: int = Field(default=10, ge=1, le=30)
    tmpfs_mb: int = Field(default=16, ge=4, le=64)


class SandboxPolicy(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    image_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    user: Literal["65532:65532"] = "65532:65532"
    network: Literal["none"] = "none"
    read_only_root: Literal[True] = True
    capabilities: Literal["DROP_ALL"] = "DROP_ALL"
    no_new_privileges: Literal[True] = True
    fixture_mount_read_only: Literal[True] = True
    harness_mount_read_only: Literal[True] = True
    host_environment_inherited: Literal[False] = False
    synthetic_credentials_only: Literal[True] = True
    resources: ResourcePolicy = Field(default_factory=ResourcePolicy)


class ExecutionContext(StrictModel):
    task_id: str = Field(pattern=r"^[a-zA-Z0-9_.-]+$")
    task_description_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    permission_profile_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class MockEvent(StrictModel):
    event_id: str
    side: Literal["OLD", "NEW"]
    category: EventCategory
    operation: str
    target: str
    detail: dict[str, Any] = Field(default_factory=dict)
    evidence_source: Literal["CONTAINER_MOCK_HARNESS"] = "CONTAINER_MOCK_HARNESS"


class RuntimeAttestation(StrictModel):
    uid: int
    gid: int
    effective_capabilities_hex: str
    no_new_privileges: bool
    seccomp_mode: Literal[2]
    apparmor_profile: str
    network_interfaces: list[str]
    environment_names: list[str]
    forbidden_environment_names: list[str]
    root_write_blocked: bool
    tmpfs_write_succeeded: bool
    fixture_source_type: Literal["CONTROLLED_MOCK"]
    harness_version: Literal["p14-mock-harness-v1"]

    @model_validator(mode="after")
    def isolation_observed(self) -> RuntimeAttestation:
        if self.uid == 0 or self.gid == 0:
            raise ValueError("container harness must not run as root")
        if self.effective_capabilities_hex.strip("0"):
            raise ValueError("effective Linux capabilities must be empty")
        if not self.no_new_privileges or self.apparmor_profile in {"", "unconfined"}:
            raise ValueError("no-new-privileges or AppArmor attestation failed")
        if self.forbidden_environment_names:
            raise ValueError("forbidden environment variables reached the container")
        if not self.root_write_blocked or not self.tmpfs_write_succeeded:
            raise ValueError("read-only root or tmpfs attestation failed")
        return self


class ContainerRunResult(StrictModel):
    side: Literal["OLD", "NEW"]
    state: Literal["COMPLETED", "FAILED", "TIMED_OUT"]
    exit_code: int | None
    events: list[MockEvent]
    attestation: RuntimeAttestation | None
    stdout_sha256: str
    stderr_sha256: str
    command_sha256: str
    command: list[str]
    duration_ms: float = Field(ge=0)
    issues: list[str] = Field(default_factory=list)
