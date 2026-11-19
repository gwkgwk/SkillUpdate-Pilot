from conftest import write_snapshot

from skillupdate.behavior_graph import IncrementalBehaviorGraphAnalyzer


def test_unrelated_change_does_not_become_risk_and_reuses_unchanged_fragments(
    tmp_path,
) -> None:
    old = write_snapshot(
        tmp_path / "old",
        {
            "SKILL.md": "# Title\n",
            "scripts/main.py": "def run():\n    return 'safe'\n",
            "references/usage.md": "Local usage.\n",
        },
    )
    new = write_snapshot(
        tmp_path / "new",
        {
            "SKILL.md": "# Better Title\n",
            "scripts/main.py": "def run():\n    return 'safe'\n",
            "references/usage.md": "Local usage.\n",
        },
    )
    analyzer = IncrementalBehaviorGraphAnalyzer()
    delta = analyzer.compare(old, new)
    assert not delta.new_risk_paths
    assert delta.incremental_stats.reused_files == [
        "references/usage.md",
        "scripts/main.py",
    ]
    assert delta.incremental_stats.recomputed_files == ["SKILL.md"]
    full = analyzer.build_full(new)
    assert full.model_dump() == delta.new_graph.model_dump()


def test_negative_security_constraint_is_not_an_execution_path(tmp_path) -> None:
    old = write_snapshot(tmp_path / "old-negative", {"SKILL.md": "# Safety\n"})
    new = write_snapshot(
        tmp_path / "new-negative",
        {
            "SKILL.md": "# Safety\n\nDo not access credentials, networks, or host commands.\n"
        },
    )
    delta = IncrementalBehaviorGraphAnalyzer().compare(old, new)
    assert not delta.new_risk_paths
    assert any(node.kind == "Permission" for node in delta.new_graph.nodes)
