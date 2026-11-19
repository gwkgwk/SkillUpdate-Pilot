"""Bounded real-provider run of HSDA + behavior graph + P13 decision."""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from run_public_dataset import discover

from skillupdate.behavior_graph import IncrementalBehaviorGraphAnalyzer
from skillupdate.decision import DecisionEngine
from skillupdate.hsda import HSDAAnalyzer
from skillupdate.llm import (
    AnalyzerConfig,
    LLMSecurityAnalyzer,
    OpenAICompatibleProvider,
    build_analysis_package,
)


def run_pair(pair, output):
    directory = Path(pair["directory"])
    hsda = HSDAAnalyzer().analyze(directory / "old", directory / "new")
    graph = IncrementalBehaviorGraphAnalyzer().compare(
        directory / "old", directory / "new"
    )
    # Task metadata excludes source categories, labels and dataset descriptions.
    package = build_analysis_package(
        pair["update_id"],
        {"identity": pair["family"]},
        "See OLD source evidence and graph for declared functionality.",
        "See NEW source evidence and graph for declared functionality.",
        hsda,
        graph,
    )
    provider = OpenAICompatibleProvider(
        endpoint="https://api.deepseek.com/chat/completions",
        api_key_env="DEEPSEEK_API_KEY",
        max_tokens_field="max_tokens",
        extra_request_fields={"thinking": {"type": "disabled"}},
    )
    analyzer = LLMSecurityAnalyzer(
        provider,
        AnalyzerConfig(
            model="deepseek-flash",
            audit_root=output / "audit",
            timeout_seconds=90,
            max_retries=0,
            max_input_tokens=100000,
            max_output_tokens=3000,
        ),
    )
    analysis = analyzer.analyze(package)
    decision = DecisionEngine().decide(package, hsda, graph, analysis)
    return {
        "update_id": pair["update_id"],
        "category": pair["category"],
        "label_scope": pair["label_scope"],
        "analysis": analysis.model_dump(mode="json"),
        "decision": decision.model_dump(mode="json"),
    }


def main(args):
    # Parse one named variable as data; do not execute a shell secret file.
    for line in args.secret_file.read_text().splitlines():
        if line.startswith("DEEPSEEK_API_KEY="):
            os.environ["DEEPSEEK_API_KEY"] = line.split("=", 1)[1].strip().strip("\"'")
    if not os.environ.get("DEEPSEEK_API_KEY"):
        raise ValueError("DEEPSEEK_API_KEY is not configured")
    pairs = discover(ROOT / "data/skill-version-dataset")
    rng = random.Random(20251117)
    selected = []
    for category in ("REAL_UPDATE_UNLABELED", "MALICIOUS_SOURCE_UPDATE"):
        selected.extend(
            rng.sample(
                sorted(
                    [p for p in pairs if p["category"] == category],
                    key=lambda p: p["update_id"],
                ),
                5,
            )
        )
    selected.extend(
        p for p in pairs if p["category"] == "CONFIRMED_INSTRUCTION_INTRODUCTION"
    )
    output = args.output_root
    output.mkdir(parents=True, exist_ok=False)
    (output / "manifest.json").write_text(
        json.dumps(
            {
                "method": "HSDA_GRAPH_LLM_DECISION",
                "model": "deepseek-flash",
                "thinking": "disabled",
                "seed": 20251117,
                "max_requests": 11,
                "max_output_tokens": 3000,
                "max_input_tokens": 100000,
                "timeout_seconds": 90,
                "dynamic_verification": False,
                "dataset_commit": "7af3c962202bdb34f5e7647c555fe29d6c83a85a",
                "selection": [
                    {"update_id": p["update_id"], "category": p["category"]}
                    for p in selected
                ],
                "ground_truth_given_to_model": False,
                "purpose": "First bounded real-model validation, not comparative performance",
            },
            indent=2,
        )
    )
    results = []
    with (
        ThreadPoolExecutor(max_workers=2) as pool,
        (output / "results.jsonl").open("w") as handle,
    ):
        futures = {pool.submit(run_pair, p, output): p["update_id"] for p in selected}
        for future in as_completed(futures):
            update_id = futures[future]
            try:
                result = future.result()
            except (ValueError, OSError, RuntimeError, RecursionError) as error:
                result = {
                    "update_id": update_id,
                    "state": "FAILED",
                    "error_type": type(error).__name__,
                }
            results.append(result)
            handle.write(json.dumps(result, ensure_ascii=False) + "\n")
            handle.flush()
            print(
                json.dumps(
                    {
                        "completed": len(results),
                        "update_id": update_id,
                        "parse_status": result.get("analysis", {}).get("parse_status"),
                        "snapshot_status": result.get("decision", {}).get(
                            "snapshot_status"
                        ),
                    }
                ),
                flush=True,
            )
    from collections import Counter

    summary = {
        "samples": len(results),
        "parse_status": dict(
            Counter(
                r.get("analysis", {}).get("parse_status", "FAILED") for r in results
            )
        ),
        "decisions": dict(
            Counter(
                r.get("decision", {}).get("snapshot_status", "FAILED") for r in results
            )
        ),
        "input_tokens": sum(
            r.get("analysis", {}).get("usage", {}).get("input_tokens", 0)
            for r in results
        ),
        "output_tokens": sum(
            r.get("analysis", {}).get("usage", {}).get("output_tokens", 0)
            for r in results
        ),
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--secret-file",
        type=Path,
        default=Path("/mnt/ssd2/gwk/.skilldetonate-secrets/deepseek.env"),
    )
    parser.add_argument("--output-root", type=Path, required=True)
    main(parser.parse_args())
