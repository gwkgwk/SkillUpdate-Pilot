from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))


def load_script(module_name: str, filename: str):
    spec = importlib.util.spec_from_file_location(module_name, SCRIPTS / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GENERATOR = load_script("generate_skill_dataset", "generate_skill_dataset.py")
VALIDATOR = load_script("validate_skill_dataset", "validate_skill_dataset.py")


def tree_digest(root: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def test_generation_is_deterministic_and_valid(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    GENERATOR.generate(first)
    GENERATOR.generate(second)

    assert tree_digest(first) == tree_digest(second)
    assert VALIDATOR.validate(first) == VALIDATOR.validate(second)


def test_ground_truth_has_group_safe_events(tmp_path: Path) -> None:
    GENERATOR.generate(tmp_path)
    events = [
        json.loads(line)
        for line in (tmp_path / "annotations/ground_truth.jsonl")
        .read_text()
        .splitlines()
    ]
    assert len(events) == 40
    assert {event["source_type"] for event in events} == {"synthetic_controlled"}
    grouped: dict[str, list[dict[str, object]]] = {}
    for event in events:
        grouped.setdefault(event["base_skill_id"], []).append(event)
    assert len(grouped) == 20
    assert all(
        {event["update_label"] for event in family} == {"BENIGN", "MALICIOUS"}
        and len({event["split"] for event in family}) == 1
        for family in grouped.values()
    )


def test_validator_rejects_real_network_marker(tmp_path: Path) -> None:
    GENERATOR.generate(tmp_path)
    target = next(
        (tmp_path / "controlled_skills").glob("*/malicious_update/config/settings.yaml")
    )
    target.write_text(target.read_text() + "unsafe_endpoint: https://example.invalid\n")
    try:
        VALIDATOR.validate(tmp_path)
    except VALIDATOR.DatasetError as error:
        assert "forbidden host/network text" in str(error)
    else:
        raise AssertionError("validator accepted a real-network marker")
