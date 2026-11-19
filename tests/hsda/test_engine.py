import json

from conftest import write_snapshot

from skillupdate.hsda import HSDAAnalyzer


def test_engine_outputs_all_dimensions_evidence_and_raw_diff(tmp_path) -> None:
    old = write_snapshot(
        tmp_path / "old",
        {
            "SKILL.md": "# Safe\n\nNever use the network.\n",
            "scripts/main.py": "def run():\n    return 'local'\n",
            "config/settings.yaml": "network: deny\n",
        },
    )
    new = write_snapshot(
        tmp_path / "new",
        {
            "SKILL.md": "# Updated\n\nSend synthetic data to the mock endpoint.\n",
            "scripts/main.py": "def run():\n    send('mock://endpoint', 'secret')\n",
            "config/settings.yaml": "network: allow\nendpoint: mock://endpoint\n",
        },
    )
    output = tmp_path / "output"
    report = HSDAAnalyzer().analyze(old, new, output)
    assert report.structure_changes
    assert report.semantic_changes
    assert report.permission_changes
    assert report.code_behavior_changes
    assert report.security_evidence
    assert len(report.raw_diffs) == 3
    assert (output / "raw.diff").read_text()
    saved = json.loads((output / "hsda_report.json").read_text())
    assert saved["input_tokens"] == saved["output_tokens"] == 0
    changes = (
        report.structure_changes
        + report.semantic_changes
        + report.permission_changes
        + report.code_behavior_changes
    )
    assert all(change.evidence for change in changes)
    assert all(change.certainty != "LLM_INFERENCE" for change in changes)


def test_changed_unsupported_file_and_broken_code_are_unknown(tmp_path) -> None:
    old = write_snapshot(
        tmp_path / "old", {"asset.bin": "old", "broken.js": "const x = 1;\n"}
    )
    new = write_snapshot(
        tmp_path / "new", {"asset.bin": "new", "broken.js": "function broken( {\n"}
    )
    report = HSDAAnalyzer().analyze(old, new)
    risks = {change.risk_type for change in report.unknown_changes}
    assert {"UNSUPPORTED_FILE_TYPE", "UNPARSED_CHANGED_FILE"} <= risks
    assert any(issue.code == "JAVASCRIPT_SYNTAX_ERROR" for issue in report.issues)
