"""Explicit-denominator metrics and Skill-cluster uncertainty for Pilot studies."""

from __future__ import annotations

import math
import random
from collections import defaultdict


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def pr_curve(labels, scores):
    if not labels or sum(labels) == 0:
        return [], None
    points = []
    area = previous_recall = 0.0
    for threshold in sorted(set(scores), reverse=True):
        selected = [i for i, score in enumerate(scores) if score >= threshold]
        tp = sum(labels[i] for i in selected)
        precision = tp / len(selected)
        recall = tp / sum(labels)
        area += (recall - previous_recall) * precision
        previous_recall = recall
        points.append(
            {"threshold": threshold, "precision": precision, "recall": recall}
        )
    return points, area


def classification(rows, axis="snapshot_status"):
    expected = "expected_" + axis
    positive = (
        {"MALICIOUS"} if axis == "snapshot_status" else {"NEW_RISK", "RISK_INCREASED"}
    )
    eligible = [r for r in rows if r.get(expected) is not None]
    decided = [r for r in eligible if r[axis] not in {"UNKNOWN", "SUSPICIOUS"}]
    tp = sum(r[expected] in positive and r[axis] in positive for r in decided)
    fp = sum(r[expected] not in positive and r[axis] in positive for r in decided)
    fn = sum(r[expected] in positive and r[axis] not in positive for r in decided)
    tn = sum(r[expected] not in positive and r[axis] not in positive for r in decided)
    p, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    scored = [r for r in eligible if r.get("malicious_score") is not None]
    curve, area = (
        pr_curve(
            [int(r[expected] in positive) for r in scored],
            [r["malicious_score"] for r in scored],
        )
        if axis == "snapshot_status"
        else ([], None)
    )
    return {
        "n": len(eligible),
        "decided": len(decided),
        "abstained": len(eligible) - len(decided),
        "coverage": ratio(len(decided), len(eligible)),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": p,
        "recall": recall,
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "fpr": ratio(fp, fp + tn),
        "fnr": ratio(fn, fn + tp),
        "exact_accuracy": ratio(
            sum(r[axis] == r[expected] for r in eligible), len(eligible)
        ),
        "end_to_end_detection_recall": ratio(
            tp, sum(r[expected] in positive for r in eligible)
        ),
        "auprc": area,
        "score_coverage": ratio(len(scored), len(eligible)),
        "pr_curve": curve,
    }


def grouped_bootstrap(rows, *, axis="snapshot_status", iterations=500, seed=20251117):
    groups = defaultdict(list)
    for row in rows:
        groups[row["base_skill_id"]].append(row)
    if len(groups) < 2:
        return {}
    rng = random.Random(seed)
    values = defaultdict(list)
    keys = sorted(groups)
    for _ in range(iterations):
        sample = [r for key in rng.choices(keys, k=len(keys)) for r in groups[key]]
        for metric, value in classification(sample, axis).items():
            if (
                metric in {"precision", "recall", "f1", "fpr", "fnr", "exact_accuracy"}
                and value is not None
            ):
                values[metric].append(value)
    result = {}
    for key, samples in values.items():
        samples.sort()
        result[key] = {
            "low": samples[int(0.025 * (len(samples) - 1))],
            "high": samples[int(0.975 * (len(samples) - 1))],
            "valid_resamples": len(samples),
            "cluster_count": len(groups),
        }
    return result


def evidence_metrics(rows):
    def counts(expected_key, predicted_key):
        eligible = [r for r in rows if r.get(expected_key) is not None]
        expected = sum(len(set(r[expected_key])) for r in eligible)
        predicted = sum(len(set(r.get(predicted_key, []))) for r in eligible)
        matched = sum(
            len(set(r[expected_key]) & set(r.get(predicted_key, []))) for r in eligible
        )
        return {
            "eligible": len(eligible),
            "matched": matched,
            "expected": expected,
            "predicted": predicted,
            "precision": ratio(matched, predicted),
            "recall": ratio(matched, expected),
        }

    return {
        "evidence": counts("expected_evidence_ids", "predicted_evidence_ids"),
        "paths": counts("expected_path_ids", "predicted_path_ids"),
    }


def efficiency(rows):
    latency = sorted(r["latency_ms"] for r in rows if r.get("latency_ms") is not None)

    def percentile(q):
        return latency[max(0, math.ceil(q * len(latency)) - 1)] if latency else None

    def total(key):
        return (
            sum(r[key] for r in rows)
            if rows and all(r.get(key) is not None for r in rows)
            else None
        )

    total_ms = sum(latency)
    return {
        "n": len(rows),
        "measured_latency_n": len(latency),
        "average_latency_ms": ratio(total_ms, len(latency)),
        "median_latency_ms": percentile(0.5),
        "p95_latency_ms": percentile(0.95),
        "input_tokens": total("input_tokens"),
        "output_tokens": total("output_tokens"),
        "total_cost_usd": total("cost_usd"),
        "sequential_throughput_per_second": ratio(len(latency) * 1000, total_ms),
        "cache_hit_rate": ratio(
            sum(r.get("cache_hit") is True for r in rows),
            sum(r.get("cache_hit") is not None for r in rows),
        ),
    }


def mcnemar_family_exact(left, right):
    """One paired unit per Skill: all events correct; exact binomial test."""

    def family_success(rows):
        groups = defaultdict(list)
        for r in rows:
            groups[r["base_skill_id"]].append(
                r["snapshot_status"] == r["expected_snapshot_status"]
            )
        return {key: all(values) for key, values in groups.items()}

    a, b = family_success(left), family_success(right)
    common = set(a) & set(b)
    ab = sum(a[k] and not b[k] for k in common)
    ba = sum(b[k] and not a[k] for k in common)
    n = ab + ba
    p = (
        min(1.0, 2 * sum(math.comb(n, i) for i in range(min(ab, ba) + 1)) / 2**n)
        if n
        else 1.0
    )
    return {
        "unit": "base_skill_all_events_correct",
        "paired_families": len(common),
        "left_only": ab,
        "right_only": ba,
        "p_value": p,
        "interpretation": "Pilot descriptive only; no significance claim",
    }
