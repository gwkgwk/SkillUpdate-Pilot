"""Static rerun on the frozen public dataset; no sample code is executed."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from skillupdate.behavior_graph import IncrementalBehaviorGraphAnalyzer
from skillupdate.hsda import HSDAAnalyzer


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def discover(root):
    pairs = []
    real = root / "01_500个真实更新skill"
    for record in read_jsonl(real / "updates.jsonl"):
        pairs.append(
            {
                "update_id": record["id"],
                "family": record["repo_full_name"] + "::" + record["skill_directory"],
                "category": "REAL_UPDATE_UNLABELED",
                "directory": str(real / record["local_directory"]),
                "metadata": record,
                "label_scope": "UNLABELED",
            }
        )
    malicious = root / "02_恶意更新skill版本"
    for base in [
        malicious / "release_versions/02_MalSkillBench",
        malicious / "release_versions/03_MaliciousSkillBench",
    ]:
        for record in read_jsonl(base / "updates.jsonl"):
            pairs.append(
                {
                    "update_id": record["id"],
                    "family": record["skill_id"],
                    "category": "MALICIOUS_SOURCE_UPDATE",
                    "directory": str(base / record["local_directory"]),
                    "metadata": record,
                    "label_scope": "NEW_SNAPSHOT_SOURCE_MEMBERSHIP_ONLY",
                }
            )
    base = malicious / "git_commit_versions/MaliciousAgentSkillsBench"
    for metadata in sorted((base / "pairs").glob("*/metadata.json")):
        record = json.loads(metadata.read_text())
        pairs.append(
            {
                "update_id": record["id"],
                "family": record["skill_id"],
                "category": "MALICIOUS_SOURCE_UPDATE",
                "directory": str(metadata.parent),
                "metadata": record,
                "label_scope": "NEW_SNAPSHOT_SOURCE_MEMBERSHIP_ONLY",
            }
        )
    base = malicious / "release_versions/01_MalSkills/confirmed_updates/MCU-0001"
    record = json.loads((base / "metadata.json").read_text())
    pairs.append(
        {
            "update_id": record["id"],
            "family": record["skill_id"],
            "category": "CONFIRMED_INSTRUCTION_INTRODUCTION",
            "directory": str(base),
            "metadata": record,
            "label_scope": "BEHAVIOR_CHANGE_ONLY_OLD_SAFETY_UNKNOWN",
        }
    )
    ids = [p["update_id"] for p in pairs]
    if len(ids) != len(set(ids)) or len(pairs) != 537:
        raise ValueError("expected exactly 537 distinct formal update pairs")
    for pair in pairs:
        directory = Path(pair["directory"]).resolve()
        if not directory.is_relative_to(root.resolve()):
            raise ValueError("pair directory escapes dataset root")
        for side in ("old", "new"):
            if not (directory / side).is_dir():
                raise ValueError(f"missing {pair['update_id']} {side}")
    return pairs


def inventory(directory):
    files = []
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError("symlink input rejected")
        if path.is_file():
            payload = path.read_bytes()
            files.append(
                {
                    "path": path.relative_to(directory).as_posix(),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "bytes": len(payload),
                }
            )
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return {"sha256": hashlib.sha256(canonical).hexdigest(), "files": files}


def main(args):
    root = args.dataset_root.resolve()
    pairs = discover(root)
    args.output_root.mkdir(parents=True, exist_ok=False)
    output = args.output_root
    manifest = {
        "dataset_commit": "7af3c962202bdb34f5e7647c555fe29d6c83a85a",
        "started_at": datetime.now(UTC).isoformat(),
        "mode": "STATIC_ONLY",
        "llm_enabled": False,
        "dynamic_enabled": False,
        "seed": 20251117,
        "pairs": len(pairs),
        "categories": dict(Counter(p["category"] for p in pairs)),
        "clones_excluded_from_update_pairs": True,
        "split": "OBSERVATIONAL_NO_TRAINING",
        "accuracy_metrics": "NOT_IDENTIFIABLE: no verified benign snapshots or pair-level safety labels",
        "code_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2))
    issues = []
    with (output / "pairs.jsonl").open("w") as pair_file:
        for i, pair in enumerate(pairs):
            directory = Path(pair["directory"])
            started = time.perf_counter()
            static = {"update_id": pair["update_id"]}
            try:
                snapshots = {
                    side: inventory(directory / side) for side in ("old", "new")
                }
                hsda = HSDAAnalyzer().analyze(directory / "old", directory / "new")
                graph = IncrementalBehaviorGraphAnalyzer().compare(
                    directory / "old", directory / "new"
                )
                target = output / "static" / pair["update_id"]
                target.mkdir(parents=True)
                (target / "hsda.json").write_text(hsda.model_dump_json())
                (target / "graph.json").write_text(graph.model_dump_json())
                static.update(
                    state="COMPLETED",
                    snapshot_inventory=snapshots,
                    hsda_issues=len(hsda.issues),
                    unknown_changes=len(hsda.unknown_changes),
                    new_risk_paths=len(graph.new_risk_paths),
                    hsda_security_evidence=len(hsda.security_evidence),
                )
            except (ValueError, OSError, RuntimeError, RecursionError) as error:
                static.update(
                    state="FAILED", error_type=type(error).__name__, error=str(error)
                )
                issues.append({"update_id": pair["update_id"], "error": str(error)})
            static["processing_ms"] = (time.perf_counter() - started) * 1000
            pair_file.write(
                json.dumps({**pair, "static": static}, ensure_ascii=False) + "\n"
            )
            pair_file.flush()
            if (i + 1) % 25 == 0:
                print(
                    json.dumps(
                        {
                            "processed": i + 1,
                            "total": len(pairs),
                            "static_failures": len(issues),
                        }
                    ),
                    flush=True,
                )
    summary = {
        "pairs": len(pairs),
        "method": "HSDA_INCREMENTAL_BEHAVIOR_GRAPH",
        "static_failures": issues,
        "completed_at": datetime.now(UTC).isoformat(),
        "limitation": "Alert rates only: neither unlabeled real updates nor source membership establish pair-level ground truth.",
    }
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False)
    )
    print(json.dumps(summary, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset-root", type=Path, default=ROOT / "data/skill-version-dataset"
    )
    parser.add_argument("--output-root", type=Path, required=True)
    main(parser.parse_args())
