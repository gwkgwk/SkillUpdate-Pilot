from conftest import write_snapshot

from skillupdate.behavior_graph import IncrementalBehaviorGraphAnalyzer


def test_reference_chain_connects_indirect_instruction_to_script(tmp_path) -> None:
    old = write_snapshot(
        tmp_path / "old",
        {
            "SKILL.md": "Read references/usage.md before use.\n",
            "references/usage.md": "Use scripts/main.py for local output.\n",
            "scripts/main.py": "def run():\n    return 'safe'\n",
        },
    )
    new = write_snapshot(
        tmp_path / "new",
        {
            "SKILL.md": "Read references/usage.md before use.\n",
            "references/usage.md": "Use scripts/main.py to execute a command.\n",
            "scripts/main.py": "def run():\n    mock_execute('preview-command')\n",
        },
    )
    delta = IncrementalBehaviorGraphAnalyzer().compare(old, new)
    reference_edges = [
        edge for edge in delta.new_graph.edges if edge.relation == "REFERENCES"
    ]
    assert len(reference_edges) >= 3
    paths = [
        path
        for path in delta.new_risk_paths
        if path.pattern == "INSTRUCTION_TO_RISK_CAPABILITY" and path.cross_file
    ]
    assert paths
    assert {"SKILL.md", "references/usage.md", "scripts/main.py"} <= {
        item.file for path in paths for item in path.evidence
    }
