"""P16 provenance schemas; marketplace claims never establish ancestry."""

from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def safe_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in value
        or "\0" in value
    ):
        raise ValueError("unsafe Skill path")
    if str(path) != value:
        raise ValueError("Skill path must be canonical POSIX")
    return value


def public_repository(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("repository must be an explicit credential-free HTTPS URL")
    path = parsed.path.rstrip("/")
    path = path.removesuffix(".git")
    if not path or path == "/":
        raise ValueError("repository URL lacks path")
    return f"https://{parsed.netloc.lower()}{path}"


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MarketplaceListing(Record):
    marketplace: str
    listing_url: str
    repository_url: str
    skill_path: str
    collected_at: str
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    resolution_status: Literal["DECLARED_UNVERIFIED", "VERIFIED"] = (
        "DECLARED_UNVERIFIED"
    )
    _repository = field_validator("repository_url")(public_repository)
    _path = field_validator("skill_path")(safe_path)


class SkillIdentity(Record):
    skill_id: str
    repository_url: str
    skill_path: str


class Snapshot(Record):
    snapshot_id: str
    skill_id: str
    commit_sha: str
    commit_time: str
    collected_at: str
    tree_sha: str
    directory_sha256: str
    files: list[dict]
    complete: bool
    issues: list[str]


class UpdateEvent(Record):
    update_id: str
    skill_id: str
    old_snapshot: str | None
    new_snapshot: str | None
    old_commit: str | None
    new_commit: str
    discovered_at: str
    event_type: Literal["INITIAL", "UPDATED", "REMOVED", "REINTRODUCED"]
    pairing_basis: Literal["FIRST_PARENT_HISTORY", "NO_BASELINE", "GAP_NO_PAIR"]
    changes: list[dict]


class RelationCandidate(Record):
    source_skill_id: str
    target_skill_id: str
    kind: Literal["COPY_OR_MIGRATION_CANDIDATE"] = "COPY_OR_MIGRATION_CANDIDATE"
    basis: Literal["EXACT_DIRECTORY_SHA256"] = "EXACT_DIRECTORY_SHA256"
    directory_sha256: str
    review_status: Literal["PENDING"] = "PENDING"
    establishes_version_relation: Literal[False] = False
