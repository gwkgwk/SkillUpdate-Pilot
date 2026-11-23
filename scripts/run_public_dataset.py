"""Static, non-executing analysis of the pinned Skill Version Dataset.

The main detection cohort is 500 user-attested benign update controls plus
53 controlled attack-content updates. 47 SkillLifeBench safety regressions
are retained as a separate diagnostic cohort. The 37 malicious-source pairs
are deliberately excluded because source membership is not pair-level impact
ground truth. Clone snapshots are not update pairs and are not included.
"""
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

DATASET_COMMIT = "864a26872f6f0a4426870c507cd82e1024a7065d"
EXPECTED_COUNTS = {
    "REAL_BENIGN_USER_ATTESTED": 500,
    "CONTROLLED_ATTACK_CONTENT": 53,
    "CONTROLLED_SAFETY_REGRESSION": 47,
}


def discover(root: Path) -> list[dict]:
    root = root.resolve()
    pairs: list[dict] = []

    real_root = root / "01_500个真实更新skill" / "verified_real_update_pairs"
    for metadata_path in sorted(real_root.glob("OPU-*/metadata.json")):
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        pair_id = metadata.get("id") or metadata_path.parent.name
        pairs.append({
            "update_id": pair_id,
            "family": f"{metadata.get('repository', 'unknown')}::{metadata.get('primary', 'unknown')}",
            "category": "REAL_BENIGN_USER_ATTESTED",
            "directory": str(metadata_path.parent.resolve()),
            "label_scope": "USER_ATTESTED_BENIGN_NOT_INDEPENDENTLY_REAUDITED",
            "label_basis": "user_attestation",
            "metadata": metadata,
        })

    controlled_root = root / "04_100对受控更新样本" / "pairs"
    for metadata_path in sorted(controlled_root.glob("CTU-*/metadata.json")):
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        pair_id = metadata.get("id") or metadata_path.parent.name
        number = int(pair_id.rsplit("-", 1)[1])
        if 1 <= number <= 47:
            category = "CONTROLLED_SAFETY_REGRESSION"
            scope = "AUTHOR_FROZEN_SCENARIO_SAFETY_REGRESSION_NOT_MALICIOUS_INTENT"
        elif 48 <= number <= 100:
            category = "CONTROLLED_ATTACK_CONTENT"
            scope = "AUTHOR_FINAL_ATTACK_LABEL_PLUS_EXACT_CONSTRUCTION_NOT_RUNTIME_VERIFIED"
        else:
            raise ValueError(f"unexpected controlled pair id: {pair_id}")
        pairs.append({
            "update_id": pair_id,
            "family": metadata.get("source_family") or metadata.get("source_host") or metadata.get("source_id") or pair_id,
            "category": category,
            "directory": str(metadata_path.parent.resolve()),
            "label_scope": scope,
            "label_basis": metadata.get("label_evidence_level"),
            "metadata": metadata,
        })

    counts = Counter(pair["category"] for pair in pairs)
    if dict(counts) != EXPECTED_COUNTS:
        raise ValueError(
            f"dataset cohort counts mismatch: expected {EXPECTED_COUNTS}, got {dict(counts)}"
        )
    ids = [pair["update_id"] for pair in pairs]
    if len(ids) != len(set(ids)) or len(pairs) != 600:
        raise ValueError("expected exactly 600 distinct update pairs")
    for pair in pairs:
        directory = Path(pair["directory"]).resolve()
        if not directory.is_relative_to(root):
            raise ValueError(f"pair directory escapes dataset root: {pair['update_id']}")
        for side in ("old", "new"):
            if not (directory / side).is_dir():
                raise ValueError(f"missing {pair['update_id']} {side} snapshot")
    return pairs


def inventory(directory: Path) -> dict:
    files = []
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"symlink input rejected: {path}")
        if path.is_file():
            payload = path.read_bytes()
            files.append({
                "path": path.relative_to(directory).as_posix(),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
            })
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return {"sha256": hashlib.sha256(canonical).hexdigest(), "files": files}


def main(args) -> None:
    root = args.dataset_root.resolve()
    pairs = discover(root)
    args.output_root.mkdir(parents=True, exist_ok=False)
    output = args.output_root
    manifest = {
        "dataset_repository": "https://github.com/gwkgwk/skill-version-dataset",
        "dataset_commit": DATASET_COMMIT,
        "started_at": datetime.now(UTC).isoformat(),
        "mode": "STATIC_ONLY",
        "sample_execution": False,
        "llm_enabled": False,
        "dynamic_enabled": False,
        "pairs": len(pairs),
        "categories": dict(Counter(p["category"] for p in pairs)),
        "main_detection_cohort": [
            "REAL_BENIGN_USER_ATTESTED",
            "CONTROLLED_ATTACK_CONTENT",
        ],
        "separate_diagnostic_cohort": ["CONTROLLED_SAFETY_REGRESSION"],
        "excluded_cohorts": {
            "malicious_source_updates": "37 pairs excluded from positive ground truth: source membership does not prove the diff introduced malicious behavior",
            "clone_snapshots": "not version update pairs",
        },
        "label_limitations": {
            "real_benign": "500 labels are user-attested; audit method and per-item review records were not supplied",
            "controlled_attack": "53 authored attack-content pairs; execution success not independently verified",
            "safety_regression": "47 author-frozen safety-regression pairs; not equivalent to malicious intent",
            "verified_real_benign_to_malicious_updates": 0,
        },
        "split": "OBSERVATIONAL_NO_TRAINING",
        "accuracy_metrics": "Do not infer aggregate accuracy/precision from heterogeneous cohorts; report each cohort separately.",
        "code_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    issues = []
    with (output / "pairs.jsonl").open("w", encoding="utf-8") as pair_file:
        for i, pair in enumerate(pairs):
            directory = Path(pair["directory"])
            started = time.perf_counter()
            static = {"update_id": pair["update_id"]}
            try:
                snapshots = {side: inventory(directory / side) for side in ("old", "new")}
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
                static.update(state="FAILED", error_type=type(error).__name__, error=str(error))
                issues.append({"update_id": pair["update_id"], "error": str(error)})
            static["processing_ms"] = (time.perf_counter() - started) * 1000
            # Labels/metadata are retained for evaluation bookkeeping only; never
            # passed to HSDA, graph analysis, or any model prompt.
            pair_file.write(json.dumps({
                "update_id": pair["update_id"],
                "family": pair["family"],
                "category": pair["category"],
                "label_scope": pair["label_scope"],
                "static": static,
            }, ensure_ascii=False) + "\n")
            pair_file.flush()
            if (i + 1) % 25 == 0:
                print(json.dumps({
                    "processed": i + 1,
                    "total": len(pairs),
                    "static_failures": len(issues),
                }), flush=True)
    summary = {
        "pairs": len(pairs),
        "categories": dict(Counter(p["category"] for p in pairs)),
        "method": "HSDA_INCREMENTAL_BEHAVIOR_GRAPH",
        "static_failures": issues,
        "completed_at": datetime.now(UTC).isoformat(),
        "limitation": "Report the 500, 53, and 47 cohorts separately; the 500 benign labels are user-attested and controlled labels are not independently re-executed.",
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    print(json.dumps(summary, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-root", type=Path, default=ROOT / "data/skill-version-dataset")
    parser.add_argument("--output-root", type=Path, required=True)
    main(parser.parse_args())
