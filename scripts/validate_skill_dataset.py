"""Validate structure, labels, hashes, splits, and safety of SkillUpdateBench."""

from __future__ import annotations

import argparse
import ast
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from generate_skill_dataset import (
    ATTACK_TYPES,
    BENIGN_TYPES,
    DATASET_ID,
    FUNCTIONS,
    REQUIRED_FILES,
    SEED,
    sha256_bytes,
    snapshot_hash,
)

FORBIDDEN_IMPORT_ROOTS = {
    "http",
    "os",
    "requests",
    "socket",
    "subprocess",
    "urllib",
}
FORBIDDEN_CALLS = {"__import__", "compile", "eval", "exec", "open"}
FORBIDDEN_ATTRIBUTES = {
    "connect",
    "getenv",
    "popen",
    "Popen",
    "request",
    "run",
    "system",
    "urlopen",
}
FORBIDDEN_TEXT = (
    "http://",
    "https://",
    "/etc/",
    "/home/",
    "/proc/",
    "/root/",
    "~/.aws",
    "~/.ssh",
)


class DatasetError(ValueError):
    """Raised when a deterministic dataset invariant is violated."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DatasetError(message)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]


def validate_python(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                require(
                    alias.name.split(".")[0] not in FORBIDDEN_IMPORT_ROOTS,
                    f"forbidden import in {path}: {alias.name}",
                )
        elif isinstance(node, ast.ImportFrom) and node.module:
            require(
                node.module.split(".")[0] not in FORBIDDEN_IMPORT_ROOTS,
                f"forbidden import in {path}: {node.module}",
            )
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                require(
                    node.func.id not in FORBIDDEN_CALLS,
                    f"forbidden call in {path}: {node.func.id}",
                )
            elif isinstance(node.func, ast.Attribute):
                require(
                    node.func.attr not in FORBIDDEN_ATTRIBUTES,
                    f"forbidden attribute call in {path}: {node.func.attr}",
                )


def validate_static_safety(snapshot_root: Path) -> None:
    for relative_path in REQUIRED_FILES:
        path = snapshot_root / relative_path
        require(not path.is_symlink(), f"symlinks are forbidden: {path}")
        text = path.read_text(encoding="utf-8")
        lower = text.lower()
        for forbidden in FORBIDDEN_TEXT:
            require(
                forbidden not in lower,
                f"forbidden host/network text in {path}: {forbidden}",
            )
        if path.suffix == ".py":
            validate_python(path)
    settings = (snapshot_root / "config/settings.yaml").read_text(encoding="utf-8")
    if "simulated_endpoint:" in settings:
        endpoint_line = next(
            line
            for line in settings.splitlines()
            if line.startswith("simulated_endpoint:")
        )
        require("mock://" in endpoint_line, f"non-mock endpoint in {snapshot_root}")


def validate_evidence(data_root: Path, event: dict[str, Any]) -> None:
    locations = event["evidence_locations"]
    require(locations, f"event has no evidence locations: {event['update_id']}")
    require(
        sorted(set(event["evidence_files"]))
        == sorted({location["file"] for location in locations}),
        f"evidence file/location mismatch: {event['update_id']}",
    )
    snapshot_root = data_root / event["new_snapshot"]["relative_path"]
    for location in locations:
        relative_path = location["file"]
        require(
            relative_path in REQUIRED_FILES, f"unknown evidence file: {relative_path}"
        )
        match = re.fullmatch(r"line:(\d+)-(\d+)", location["locator"])
        require(match is not None, f"invalid locator: {location['locator']}")
        start, end = (int(value) for value in match.groups())
        lines = (snapshot_root / relative_path).read_text(encoding="utf-8").splitlines()
        require(
            1 <= start <= end <= len(lines),
            f"out-of-range locator: {event['update_id']}",
        )
        require(
            location["marker"] in "\n".join(lines[start - 1 : end]),
            f"marker mismatch: {event['update_id']}",
        )


def validate(data_root: Path) -> dict[str, Any]:
    controlled_root = data_root / "controlled_skills"
    annotations_root = data_root / "annotations"
    manifests_root = data_root / "manifests"
    manifest = load_json(manifests_root / "dataset_manifest.json")
    splits_document = load_json(manifests_root / "splits.json")
    generation = load_json(manifests_root / "generation_manifest.json")
    events = load_jsonl(annotations_root / "ground_truth.jsonl")

    require(manifest["dataset_id"] == DATASET_ID, "wrong dataset id")
    require(manifest["seed"] == SEED, "wrong seed")
    require(manifest["source_type"] == "synthetic_controlled", "wrong source type")
    require(
        manifest["counts"]
        == {
            "base_skills": 20,
            "snapshots": 60,
            "benign_updates": 20,
            "malicious_updates": 20,
        },
        "wrong manifest counts",
    )
    require(
        manifest["function_types"] == {key: 4 for key in FUNCTIONS},
        "wrong function counts",
    )
    require(
        manifest["safety"]
        == {
            "real_credentials": False,
            "real_network": False,
            "host_command_execution": False,
            "mock_endpoints_only": True,
            "in_memory_audit_only": True,
        },
        "unsafe manifest policy",
    )

    skill_directories = sorted(
        path for path in controlled_root.iterdir() if path.is_dir()
    )
    require(len(skill_directories) == 20, "expected exactly 20 base skill directories")
    expected_snapshot_paths: set[str] = set()
    observed_snapshot_hashes: dict[str, str] = {}
    for skill_root in skill_directories:
        variants = sorted(path.name for path in skill_root.iterdir() if path.is_dir())
        require(
            variants == ["base", "benign_update", "malicious_update"],
            f"wrong variants for {skill_root.name}",
        )
        for variant in variants:
            snapshot_root = skill_root / variant
            actual_files = sorted(
                path.relative_to(snapshot_root).as_posix()
                for path in snapshot_root.rglob("*")
                if path.is_file()
            )
            require(
                actual_files == sorted(REQUIRED_FILES),
                f"wrong file set in {snapshot_root}",
            )
            validate_static_safety(snapshot_root)
            digest, _ = snapshot_hash(snapshot_root)
            relative_path = snapshot_root.relative_to(data_root).as_posix()
            expected_snapshot_paths.add(relative_path)
            observed_snapshot_hashes[relative_path] = digest

    snapshot_records = manifest["snapshots"]
    require(len(snapshot_records) == 60, "expected 60 snapshot records")
    require(
        {row["relative_path"] for row in snapshot_records} == expected_snapshot_paths,
        "snapshot manifest path mismatch",
    )
    for row in snapshot_records:
        require(
            observed_snapshot_hashes[row["relative_path"]] == row["sha256"],
            f"snapshot hash mismatch: {row['relative_path']}",
        )

    require(len(events) == 40, "expected 40 update annotations")
    required_fields = set(
        load_json(annotations_root / "annotation_schema.json")["required_fields"]
    )
    require(len({event["update_id"] for event in events}) == 40, "duplicate update ids")
    labels = Counter(event["update_label"] for event in events)
    require(labels == {"BENIGN": 20, "MALICIOUS": 20}, "wrong label counts")
    by_skill: dict[str, list[dict[str, Any]]] = defaultdict(list)
    attack_coverage: set[str] = set()
    benign_coverage: set[str] = set()
    function_counts: Counter[str] = Counter()
    for event in events:
        require(
            required_fields <= event.keys(),
            f"missing annotation field: {event['update_id']}",
        )
        require(
            event["source_type"] == "synthetic_controlled",
            f"wrong event source: {event['update_id']}",
        )
        require(event["random_seed"] == SEED, f"wrong event seed: {event['update_id']}")
        require(
            event["old_snapshot"]["relative_path"].endswith("/base"),
            f"wrong old snapshot: {event['update_id']}",
        )
        expected_variant = (
            "benign_update" if event["update_label"] == "BENIGN" else "malicious_update"
        )
        require(
            event["new_snapshot"]["relative_path"].endswith(f"/{expected_variant}"),
            f"wrong new snapshot: {event['update_id']}",
        )
        for snapshot in (event["old_snapshot"], event["new_snapshot"]):
            require(
                observed_snapshot_hashes[snapshot["relative_path"]]
                == snapshot["sha256"],
                f"annotation hash mismatch: {event['update_id']}",
            )
        validate_evidence(data_root, event)
        by_skill[event["base_skill_id"]].append(event)
        if event["update_label"] == "BENIGN":
            require(
                not event["attack_types"],
                f"benign event has attack type: {event['update_id']}",
            )
            require(
                not event["expected_attack_path"],
                f"benign event has attack path: {event['update_id']}",
            )
            benign_coverage.update(event["change_types"])
            function_counts[event["function_type"]] += 1
        else:
            require(
                event["attack_types"],
                f"malicious event has no attack type: {event['update_id']}",
            )
            require(
                event["expected_attack_path"],
                f"malicious event has no attack path: {event['update_id']}",
            )
            attack_coverage.update(event["attack_types"])
    require(
        len(by_skill) == 20 and all(len(rows) == 2 for rows in by_skill.values()),
        "each base skill needs two update events",
    )
    require(attack_coverage == set(ATTACK_TYPES), "attack type coverage incomplete")
    require(benign_coverage == set(BENIGN_TYPES), "benign change coverage incomplete")
    require(
        function_counts == {key: 4 for key in FUNCTIONS},
        "functional type coverage incomplete",
    )

    require(
        splits_document["dataset_id"] == DATASET_ID and splits_document["seed"] == SEED,
        "split metadata mismatch",
    )
    require(splits_document["group_key"] == "base_skill_id", "wrong split group key")
    splits = splits_document["splits"]
    require(
        {name: len(ids) for name, ids in splits.items()}
        == {"train": 10, "validation": 5, "test": 5},
        "wrong split sizes",
    )
    split_sets = {name: set(ids) for name, ids in splits.items()}
    require(
        not (
            split_sets["train"] & split_sets["validation"]
            or split_sets["train"] & split_sets["test"]
            or split_sets["validation"] & split_sets["test"]
        ),
        "base_skill_id split leakage",
    )
    require(
        set().union(*split_sets.values()) == set(by_skill), "split coverage mismatch"
    )
    for base_skill_id, skill_events in by_skill.items():
        assigned = {event["split"] for event in skill_events}
        require(len(assigned) == 1, f"event split leakage for {base_skill_id}")

    require(
        generation["ground_truth_sha256"]
        == sha256_bytes((annotations_root / "ground_truth.jsonl").read_bytes()),
        "ground truth digest mismatch",
    )
    require(
        generation["dataset_manifest_sha256"]
        == sha256_bytes((manifests_root / "dataset_manifest.json").read_bytes()),
        "dataset manifest digest mismatch",
    )
    require(
        generation["splits_sha256"]
        == sha256_bytes((manifests_root / "splits.json").read_bytes()),
        "split digest mismatch",
    )
    return {
        "dataset_id": DATASET_ID,
        "base_skills": len(by_skill),
        "updates": len(events),
        "snapshots": len(snapshot_records),
        "labels": dict(sorted(labels.items())),
        "splits": {name: len(ids) for name, ids in splits.items()},
        "status": "VALID",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-root",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "data",
    )
    args = parser.parse_args()
    try:
        result = validate(args.data_root.resolve())
    except (
        DatasetError,
        FileNotFoundError,
        json.JSONDecodeError,
        SyntaxError,
    ) as error:
        print(json.dumps({"status": "INVALID", "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
