"""Offline collector, identities, content snapshots, SQLite and event detection."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from .models import (
    MarketplaceListing,
    RelationCandidate,
    SkillIdentity,
    Snapshot,
    UpdateEvent,
    digest,
    public_repository,
    safe_path,
)


def now():
    return datetime.now(UTC).isoformat()


class MarketplaceCollector:
    """Import archived public listing records; no scraping/network in phase 1."""

    def collect(self, archived_json: str | Path) -> list[MarketplaceListing]:
        payload = Path(archived_json).read_bytes()
        evidence_hash = hashlib.sha256(payload).hexdigest()
        records = json.loads(payload)
        return [
            MarketplaceListing(**r, collected_at=now(), evidence_sha256=evidence_hash)
            for r in records
        ]


class RepositoryResolver:
    def resolve(self, listing: MarketplaceListing):
        return {
            "repository_url": public_repository(listing.repository_url),
            "skill_path": safe_path(listing.skill_path),
            "status": listing.resolution_status,
            "evidence_sha256": listing.evidence_sha256,
        }


class SkillIdentityManager:
    def identify(self, repository_url: str, skill_path: str):
        repository_url = public_repository(repository_url)
        skill_path = safe_path(skill_path)
        return SkillIdentity(
            skill_id="skill-" + digest([repository_url, skill_path]),
            repository_url=repository_url,
            skill_path=skill_path,
        )


class MetadataDatabase:
    def __init__(self, path: str | Path):
        self.connection = sqlite3.connect(path)
        self.connection.executescript("""
        PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS records(kind TEXT,id TEXT,payload TEXT,PRIMARY KEY(kind,id));
        CREATE TABLE IF NOT EXISTS sightings(kind TEXT,id TEXT,observed_at TEXT);
        CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY,event_id TEXT,evidence TEXT,created_at TEXT);
        CREATE TABLE IF NOT EXISTS reviews(id INTEGER PRIMARY KEY,alert_id TEXT REFERENCES alerts(id),
          reviewer TEXT,verdict TEXT,note TEXT,reviewed_at TEXT);
        """)

    def save(self, kind, key, payload):
        encoded = json.dumps(payload, sort_keys=True)
        existing = self.connection.execute(
            "SELECT payload FROM records WHERE kind=? AND id=?", (kind, key)
        ).fetchone()
        if existing is None:
            self.connection.execute(
                "INSERT INTO records VALUES(?,?,?)", (kind, key, encoded)
            )
        self.connection.execute(
            "INSERT INTO sightings VALUES(?,?,?)", (kind, key, now())
        )
        self.connection.commit()

    def records(self, kind):
        return [
            json.loads(row[0])
            for row in self.connection.execute(
                "SELECT payload FROM records WHERE kind=? ORDER BY id", (kind,)
            )
        ]

    def alert(self, event_id, evidence):
        if not evidence:
            raise ValueError("risk alert requires source evidence")
        if not self.connection.execute(
            "SELECT 1 FROM records WHERE kind=? AND id=?", ("event", event_id)
        ).fetchone():
            raise ValueError("alert must reference an existing event")
        alert_id = "alert-" + digest([event_id, evidence])
        self.connection.execute(
            "INSERT OR IGNORE INTO alerts VALUES(?,?,?,?)",
            (alert_id, event_id, json.dumps(evidence), now()),
        )
        self.connection.commit()
        return {
            "alert_id": alert_id,
            "review_status": "PENDING",
            "review_entry": f"sqlite:reviews/{alert_id}",
        }

    def review(self, alert_id, reviewer, verdict, note):
        if (
            verdict not in {"CONFIRMED", "REJECTED", "UNCERTAIN"}
            or not reviewer
            or not note
        ):
            raise ValueError("review requires named reviewer, verdict and note")
        self.connection.execute(
            "INSERT INTO reviews(alert_id,reviewer,verdict,note,reviewed_at) VALUES(?,?,?,?,?)",
            (alert_id, reviewer, verdict, note, now()),
        )
        self.connection.commit()


class SnapshotManager:
    def __init__(self, root: str | Path, max_bytes=16 * 1024 * 1024, max_files=1024):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.max_files = max_files

    def capture(self, history, identity, commit):
        entries = history.directory(commit, identity.skill_path)
        if not any(
            path == "SKILL.md" and mode in {"100644", "100755"}
            for path, mode, _, _ in entries
        ):
            return None
        if len(entries) > self.max_files:
            raise ValueError("snapshot file count limit exceeded")
        files = []
        issues = []
        total = 0
        for path, mode, kind, oid in entries:
            if kind != "blob":
                files.append(
                    {
                        "path": path,
                        "mode": mode,
                        "git_oid": oid,
                        "sha256": None,
                        "size": None,
                    }
                )
                issues.append(f"UNEXPANDED_GITLINK:{path}")
                continue
            payload = history.blob(oid, self.max_bytes - total)
            if payload.startswith(b"version https://git-lfs.github.com/spec/v1\n"):
                issues.append(f"UNEXPANDED_LFS_POINTER:{path}")
            total += len(payload)
            sha = hashlib.sha256(payload).hexdigest()
            blob = self.root / "blobs" / sha
            blob.parent.mkdir(exist_ok=True)
            if blob.exists() and hashlib.sha256(blob.read_bytes()).hexdigest() != sha:
                raise ValueError("content-addressed blob integrity failure")
            if not blob.exists():
                blob.write_bytes(payload)
            files.append(
                {
                    "path": path,
                    "mode": mode,
                    "git_oid": oid,
                    "sha256": sha,
                    "size": len(payload),
                }
            )
            if mode == "120000":
                issues.append(f"SYMLINK_RECORDED_NOT_FOLLOWED:{path}")
        directory_hash = digest(files)
        snapshot_id = "snap-" + digest([identity.skill_id, commit, directory_hash])
        tree = history.git("rev-parse", commit + "^{tree}").decode().strip()
        result = Snapshot(
            snapshot_id=snapshot_id,
            skill_id=identity.skill_id,
            commit_sha=commit,
            commit_time=history.git("show", "-s", "--format=%cI", commit)
            .decode()
            .strip(),
            collected_at=now(),
            tree_sha=tree,
            directory_sha256=directory_hash,
            files=files,
            complete=not any(i.startswith("UNEXPANDED") for i in issues),
            issues=issues,
        )
        manifest = self.root / (snapshot_id + ".json")
        if not manifest.exists():
            manifest.write_text(result.model_dump_json(indent=2))
        return result


class UpdateEventDetector:
    def diff(self, old, new):
        before = {r["path"]: r for r in old.files} if old else {}
        after = {r["path"]: r for r in new.files} if new else {}
        removed = set(before) - set(after)
        added = set(after) - set(before)
        changes = []
        # Conservative, unique exact-content rename only; ambiguity stays add/delete.
        for path in sorted(removed):
            key = (before[path]["sha256"], before[path]["mode"])
            matches = [
                p for p in added if (after[p]["sha256"], after[p]["mode"]) == key
            ]
            sources = [
                p for p in removed if (before[p]["sha256"], before[p]["mode"]) == key
            ]
            if key[0] and len(matches) == len(sources) == 1:
                target = matches[0]
                changes.append(
                    {
                        "type": "RENAMED",
                        "old_path": path,
                        "new_path": target,
                        "basis": "UNIQUE_EXACT_CONTENT",
                    }
                )
                removed.remove(path)
                added.remove(target)
        changes.extend(
            {"type": "DELETED", "old_path": p, "new_path": None}
            for p in sorted(removed)
        )
        changes.extend(
            {"type": "ADDED", "old_path": None, "new_path": p} for p in sorted(added)
        )
        changes.extend(
            {"type": "MODIFIED", "old_path": p, "new_path": p}
            for p in sorted(set(before) & set(after))
            if before[p] != after[p]
        )
        return changes

    def relation_candidates(self, snapshots):
        grouped = defaultdict(set)
        for snapshot in snapshots:
            if not snapshot.complete:
                continue
            grouped[snapshot.directory_sha256].add(snapshot.skill_id)
        return [
            RelationCandidate(
                source_skill_id=a, target_skill_id=b, directory_sha256=sha
            )
            for sha, skills in sorted(grouped.items())
            for a in sorted(skills)
            for b in sorted(skills)
            if a < b
        ]


class OfflineHistoryReconstructor:
    def __init__(self, database: MetadataDatabase, snapshots: SnapshotManager):
        self.database = database
        self.snapshots = snapshots

    def reconstruct(self, repository, repository_url, skill_path, head_sha):
        from skillupdate.versioning.history import GitHistory

        history = GitHistory(repository)
        identity = SkillIdentityManager().identify(repository_url, skill_path)
        self.database.save("identity", identity.skill_id, identity.model_dump())
        previous = None
        seen = False
        last_commit = None
        events = []
        detector = UpdateEventDetector()
        for commit in history.commits(head_sha):
            current = self.snapshots.capture(history, identity, commit)
            if current:
                self.database.save(
                    "snapshot", current.snapshot_id, current.model_dump()
                )
            changed = (current is None) != (previous is None) or (
                current
                and previous
                and current.directory_sha256 != previous.directory_sha256
            )
            if changed:
                event_type = (
                    "REMOVED"
                    if current is None
                    else "UPDATED"
                    if previous
                    else "REINTRODUCED"
                    if seen
                    else "INITIAL"
                )
                event = UpdateEvent(
                    update_id="update-"
                    + digest([identity.skill_id, last_commit, commit, event_type]),
                    skill_id=identity.skill_id,
                    old_snapshot=previous.snapshot_id if previous else None,
                    new_snapshot=current.snapshot_id if current else None,
                    old_commit=last_commit,
                    new_commit=commit,
                    discovered_at=now(),
                    event_type=event_type,
                    pairing_basis="FIRST_PARENT_HISTORY"
                    if previous
                    else "GAP_NO_PAIR"
                    if seen
                    else "NO_BASELINE",
                    changes=detector.diff(previous, current),
                )
                self.database.save("event", event.update_id, event.model_dump())
                events.append(event)
            seen = seen or current is not None
            previous = current
            last_commit = commit
        all_snapshots = [
            Snapshot.model_validate(row) for row in self.database.records("snapshot")
        ]
        for candidate in detector.relation_candidates(all_snapshots):
            self.database.save(
                "relation_candidate",
                digest(candidate.model_dump()),
                candidate.model_dump(),
            )
        self.database.save(
            "reconstruction",
            digest([identity.skill_id, head_sha]),
            {
                "skill_id": identity.skill_id,
                "head_sha": head_sha,
                "collected_at": now(),
                "source_resolution": "CALLER_DECLARED_UNVERIFIED",
                "history_policy": "FIRST_PARENT",
                "event_count": len(events),
            },
        )
        return events
