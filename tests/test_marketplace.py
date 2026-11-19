from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skillupdate.marketplace import (
    MarketplaceCollector,
    MetadataDatabase,
    OfflineHistoryReconstructor,
    SkillIdentityManager,
    SnapshotManager,
    UpdateEventDetector,
)
from skillupdate.marketplace.models import Snapshot
from skillupdate.versioning.history import GitHistory


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


@pytest.fixture
def repository(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.name", "Fixture")
    git(repo, "config", "user.email", "fixture@example.invalid")
    skill = repo / "skills" / "example"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# Example\n")
    (skill / "old.txt").write_bytes(b"\x00binary\xff")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "initial")
    (skill / "old.txt").rename(skill / "new.txt")
    (skill / "SKILL.md").write_text("# Updated example\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "update")
    return repo


def test_identity_requires_repository_and_path():
    manager = SkillIdentityManager()
    a = manager.identify("https://github.com/a/repo.git", "skills/example")
    assert a == manager.identify("https://github.com/a/repo", "skills/example")
    assert (
        a.skill_id
        != manager.identify("https://github.com/b/repo", "skills/example").skill_id
    )
    assert a.skill_id != manager.identify(a.repository_url, "other/example").skill_id
    with pytest.raises(ValueError):
        manager.identify("https://user:secret@example.com/repo", "skills/example")


def test_history_snapshots_and_exact_rename(repository, tmp_path):
    db = MetadataDatabase(tmp_path / "metadata.sqlite")
    store = SnapshotManager(tmp_path / "snapshots")
    recon = OfflineHistoryReconstructor(db, store)
    events = recon.reconstruct(
        repository,
        "https://github.com/example/repo",
        "skills/example",
        git(repository, "rev-parse", "HEAD"),
    )
    assert [e.event_type for e in events] == ["INITIAL", "UPDATED"]
    assert {"RENAMED", "MODIFIED"} == {c["type"] for c in events[-1].changes}
    snapshots = db.records("snapshot")
    for snapshot in snapshots:
        for file in snapshot["files"]:
            blob = (store.root / "blobs" / file["sha256"]).read_bytes()
            assert hashlib.sha256(blob).hexdigest() == file["sha256"]
    assert b"\x00binary\xff" in [
        p.read_bytes() for p in (store.root / "blobs").iterdir()
    ]
    recon.reconstruct(
        repository,
        "https://github.com/example/repo",
        "skills/example",
        git(repository, "rev-parse", "HEAD"),
    )
    assert len(db.records("event")) == 2


def test_deletion_reintroduction_no_gap_pair(repository, tmp_path):
    skill = repository / "skills/example/SKILL.md"
    content = skill.read_text()
    skill.unlink()
    git(repository, "add", "-A")
    git(repository, "commit", "-qm", "remove")
    skill.write_text(content)
    git(repository, "add", "-A")
    git(repository, "commit", "-qm", "restore")
    db = MetadataDatabase(tmp_path / "db")
    events = OfflineHistoryReconstructor(
        db, SnapshotManager(tmp_path / "cas")
    ).reconstruct(
        repository,
        "https://github.com/example/repo",
        "skills/example",
        git(repository, "rev-parse", "HEAD"),
    )
    assert events[-2].event_type == "REMOVED"
    assert events[-1].event_type == "REINTRODUCED"
    assert events[-1].old_snapshot is None and events[-1].pairing_basis == "GAP_NO_PAIR"


def test_copy_candidate_does_not_establish_version(repository, tmp_path):
    db = MetadataDatabase(tmp_path / "db")
    recon = OfflineHistoryReconstructor(db, SnapshotManager(tmp_path / "cas"))
    for owner in ("alice", "bob"):
        recon.reconstruct(
            repository,
            f"https://github.com/{owner}/repo",
            "skills/example",
            git(repository, "rev-parse", "HEAD"),
        )
    candidates = UpdateEventDetector().relation_candidates(
        [Snapshot.model_validate(s) for s in db.records("snapshot")]
    )
    assert candidates and all(not c.establishes_version_relation for c in candidates)


def test_alert_requires_human_review_record(repository, tmp_path):
    db = MetadataDatabase(tmp_path / "db")
    events = OfflineHistoryReconstructor(
        db, SnapshotManager(tmp_path / "cas")
    ).reconstruct(
        repository,
        "https://github.com/example/repo",
        "skills/example",
        git(repository, "rev-parse", "HEAD"),
    )
    alert = db.alert(
        events[-1].update_id, {"file": "SKILL.md", "commit": events[-1].new_commit}
    )
    assert alert["review_status"] == "PENDING"
    db.review(alert["alert_id"], "reviewer-one", "UNCERTAIN", "Need evidence review")
    assert db.connection.execute("SELECT count(*) FROM reviews").fetchone()[0] == 1


def test_no_revision_options_or_traversal(repository):
    history = GitHistory(repository)
    with pytest.raises(ValueError):
        history.commits("--all")
    with pytest.raises(ValueError):
        history.directory(git(repository, "rev-parse", "HEAD"), "../outside")


def test_symlink_and_lfs_are_recorded_without_following(repository, tmp_path):
    skill = repository / "skills/example"
    (skill / "link").symlink_to("/nonexistent/host-secret")
    (skill / "large.dat").write_text(
        "version https://git-lfs.github.com/spec/v1\noid sha256:fake\nsize 123\n"
    )
    git(repository, "add", "-A")
    git(repository, "commit", "-qm", "opaque resources")
    history = GitHistory(repository)
    identity = SkillIdentityManager().identify(
        "https://github.com/example/repo", "skills/example"
    )
    snapshot = SnapshotManager(tmp_path / "cas").capture(
        history, identity, git(repository, "rev-parse", "HEAD")
    )
    assert snapshot.complete is False
    assert any(i.startswith("SYMLINK_RECORDED") for i in snapshot.issues)
    assert any(i.startswith("UNEXPANDED_LFS") for i in snapshot.issues)


def test_archived_collector_preserves_provenance(tmp_path):
    archive = tmp_path / "listings.json"
    archive.write_text(
        json.dumps(
            [
                {
                    "marketplace": "SkillsMP",
                    "listing_url": "https://skillsmp.com/example",
                    "repository_url": "https://github.com/a/repo",
                    "skill_path": "skills/example",
                }
            ]
        )
    )
    listing = MarketplaceCollector().collect(archive)[0]
    assert listing.resolution_status == "DECLARED_UNVERIFIED"
    assert listing.evidence_sha256 == hashlib.sha256(archive.read_bytes()).hexdigest()
