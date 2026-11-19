"""P16 offline Git Skill history CLI. No fetch, checkout, or execution."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from skillupdate.marketplace import (
    MetadataDatabase,
    OfflineHistoryReconstructor,
    SnapshotManager,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--repository-url", required=True)
    parser.add_argument("--skill-path", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    args.output_root.mkdir(parents=True, exist_ok=False)
    database = MetadataDatabase(args.output_root / "metadata.sqlite")
    events = OfflineHistoryReconstructor(
        database, SnapshotManager(args.output_root / "snapshots")
    ).reconstruct(args.repository, args.repository_url, args.skill_path, args.head_sha)
    (args.output_root / "events.jsonl").write_text(
        "".join(e.model_dump_json() + "\n" for e in events)
    )
    print(
        json.dumps(
            {
                "status": "COMPLETED",
                "events": len(events),
                "snapshots": len(database.records("snapshot")),
                "source_resolution": "CALLER_DECLARED_UNVERIFIED",
                "network_used": False,
            }
        )
    )


if __name__ == "__main__":
    main()
