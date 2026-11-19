"""Real dataset adapter tests: preserve uncertainty and reject escaping paths."""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location(
    "public_runner", ROOT / "scripts/run_public_dataset.py"
)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


@pytest.mark.skipif(
    not (ROOT / "data/skill-version-dataset").is_dir(),
    reason="optional public dataset has not been downloaded; see README",
)
def test_formal_pairs_preserve_label_scope():
    pairs = runner.discover(ROOT / "data/skill-version-dataset")
    assert len(pairs) == 537
    assert sum(p["label_scope"] == "UNLABELED" for p in pairs) == 500
    assert (
        sum(p["label_scope"] == "NEW_SNAPSHOT_SOURCE_MEMBERSHIP_ONLY" for p in pairs)
        == 36
    )
    assert (
        sum(
            p["label_scope"] == "BEHAVIOR_CHANGE_ONLY_OLD_SAFETY_UNKNOWN" for p in pairs
        )
        == 1
    )
    assert not any("03_恶意skill克隆版本" in p["directory"] for p in pairs)


def test_inventory_hashes_bytes_not_decoded_text(tmp_path):
    (tmp_path / "binary").write_bytes(b"\xff\x00\x01")
    result = runner.inventory(tmp_path)
    assert result["files"][0]["bytes"] == 3
    (tmp_path / "binary").write_bytes(b"\xfe\x00\x01")
    assert runner.inventory(tmp_path)["sha256"] != result["sha256"]
