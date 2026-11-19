"""Label-isolated aggregation with explicit missing strata and audit hashes."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from itertools import combinations
from pathlib import Path

from .metrics import (
    classification,
    efficiency,
    evidence_metrics,
    grouped_bootstrap,
    mcnemar_family_exact,
    ratio,
)

SOURCES = [
    "BENIGN_UPDATES",
    "REAL_WORLD_MALICIOUS",
    "CONTROLLED_MALICIOUS",
    "ADVERSARIAL",
]
TRANSFORMS = [
    "Natural Language Rewriting",
    "Instruction Splitting",
    "Reference Indirection",
    "Code Obfuscation",
    "Benign Feature Camouflage",
    "Prompt Injection",
    "Trigger-based Behavior",
]


def validate_groups(records):
    groups = {}
    ids = set()
    for r in records:
        if r["source_category"] not in SOURCES or r["scenario"] not in {
            "T1",
            "T2",
            "T3",
            "T4",
        }:
            raise ValueError("invalid source category or update scenario")
        if r["update_id"] in ids:
            raise ValueError("duplicate update_id")
        ids.add(r["update_id"])
        family, split = r["base_skill_id"], r["split"]
        if family in groups and groups[family] != split:
            raise ValueError("Skill family crosses dataset splits")
        groups[family] = split
        if r.get("source_category") == "ADVERSARIAL":
            if not r.get("independent_annotation_verified") or not r.get(
                "controlled_semantics_verified"
            ):
                raise ValueError(
                    "adversarial labels require independent annotation and controlled verification"
                )
            if r.get("transformation") not in TRANSFORMS:
                raise ValueError("unknown adversarial transformation")
    by_id = {r["update_id"]: r for r in records}
    for r in records:
        if r.get("parent_update_id"):
            parent = by_id[r["parent_update_id"]]
            if (parent["base_skill_id"], parent["split"]) != (
                r["base_skill_id"],
                r["split"],
            ):
                raise ValueError("attack variant crosses family or split")


def evaluate(records, predictions, *, iterations=500, seed=20251117):
    validate_groups(records)
    truth = {r["update_id"]: r for r in records}
    joined = defaultdict(list)
    seen = set()
    for p in predictions:
        if p.get("malicious_score") is not None and not 0 <= p["malicious_score"] <= 1:
            raise ValueError("malicious_score must be a probability")
        key = (p["method"], p["update_id"])
        if key in seen:
            raise ValueError("duplicate method/update prediction")
        seen.add(key)
        if p["update_id"] not in truth:
            raise ValueError("prediction has no annotation")
        joined[p["method"]].append({**p, **truth[p["update_id"]]})
    reports = []
    for method, rows in sorted(joined.items()):
        if {r["update_id"] for r in rows} != set(truth):
            raise ValueError("all methods must use exactly the same evaluation records")
        for split in sorted({r["split"] for r in rows}):
            for source in SOURCES:
                for scenario in ("ALL", "T1", "T2", "T3", "T4"):
                    subset = [
                        r
                        for r in rows
                        if r["split"] == split
                        and r["source_category"] == source
                        and (scenario == "ALL" or r["scenario"] == scenario)
                    ]
                    reports.append(
                        dict(
                            method=method,
                            split=split,
                            source=source,
                            scenario=scenario,
                            state="AVAILABLE" if subset else "NO_DATA",
                            n=len(subset),
                            snapshot=classification(subset),
                            impact=classification(subset, "update_impact"),
                            snapshot_ci=grouped_bootstrap(
                                subset, iterations=iterations, seed=seed
                            ),
                            impact_ci=grouped_bootstrap(
                                subset,
                                axis="update_impact",
                                iterations=iterations,
                                seed=seed,
                            ),
                            **evidence_metrics(subset),
                            efficiency=efficiency(subset),
                        )
                    )
    adversarial = []
    for method, rows in joined.items():
        by_id = {r["update_id"]: r for r in rows}
        for transform in TRANSFORMS:
            eligible = [
                r
                for r in rows
                if r.get("transformation") == transform
                and r.get("parent_update_id") in by_id
                and by_id[r["parent_update_id"]]["snapshot_status"] == "MALICIOUS"
            ]
            adversarial.append(
                {
                    "method": method,
                    "transformation": transform,
                    "n": len(eligible),
                    "asr": ratio(
                        sum(r["snapshot_status"] == "BENIGN" for r in eligible),
                        len(eligible),
                    ),
                    "abstention_rate": ratio(
                        sum(
                            r["snapshot_status"] in {"UNKNOWN", "SUSPICIOUS"}
                            for r in eligible
                        ),
                        len(eligible),
                    ),
                }
            )
    errors = [
        {
            "method": m,
            "update_id": r["update_id"],
            "split": r["split"],
            "expected": r["expected_snapshot_status"],
            "actual": r["snapshot_status"],
            "evidence": r.get("evidence", []),
        }
        for m, rows in joined.items()
        for r in rows
        if r["snapshot_status"] != r["expected_snapshot_status"]
    ]
    paired_tests = []
    for left, right in combinations(sorted(joined), 2):
        for source in SOURCES:
            lrows = [
                r
                for r in joined[left]
                if r["split"] == "test" and r["source_category"] == source
            ]
            rrows = [
                r
                for r in joined[right]
                if r["split"] == "test" and r["source_category"] == source
            ]
            if lrows and rrows:
                paired_tests.append(
                    {
                        "left": left,
                        "right": right,
                        "source": source,
                        **mcnemar_family_exact(lrows, rrows),
                    }
                )
    return {
        "paired_family_tests": paired_tests,
        "pilot": True,
        "significance_claim": False,
        "reports": reports,
        "adversarial": adversarial,
        "errors": errors,
    }


def write_json(path, value):
    Path(path).write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def file_digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
