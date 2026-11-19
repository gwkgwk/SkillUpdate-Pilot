from conftest import write_snapshot

from skillupdate.behavior_graph import IncrementalBehaviorGraphAnalyzer


def test_file_and_function_rename_align_by_content_and_structure(tmp_path) -> None:
    old = write_snapshot(
        tmp_path / "old", {"scripts/old_name.py": "def old_name():\n    return 1\n"}
    )
    new = write_snapshot(
        tmp_path / "new", {"scripts/new_name.py": "def new_name():\n    return 1\n"}
    )
    delta = IncrementalBehaviorGraphAnalyzer().compare(old, new)
    methods = {alignment.method for alignment in delta.node_alignments}
    assert "FUNCTION_STRUCTURE" in methods
    assert (
        any(
            alignment.method == "FILE_CONTENT_RENAME"
            for alignment in delta.node_alignments
        )
        is False
    )
    function_alignment = next(
        alignment
        for alignment in delta.node_alignments
        if alignment.method == "FUNCTION_STRUCTURE"
    )
    assert function_alignment.confidence == 0.95


def test_exact_file_rename_and_same_name_refactor_alignment(tmp_path) -> None:
    old = write_snapshot(
        tmp_path / "old", {"scripts/a.py": "def run():\n    return 1\n"}
    )
    renamed = write_snapshot(
        tmp_path / "renamed", {"scripts/b.py": "def run():\n    return 1\n"}
    )
    rename_delta = IncrementalBehaviorGraphAnalyzer().compare(old, renamed)
    assert any(
        alignment.method == "FILE_CONTENT_RENAME"
        for alignment in rename_delta.node_alignments
    )
    refactored = write_snapshot(
        tmp_path / "refactored",
        {"scripts/a.py": "def run():\n    value = 1\n    return value\n"},
    )
    refactor_delta = IncrementalBehaviorGraphAnalyzer().compare(old, refactored)
    old_functions = {
        node.node_id
        for node in refactor_delta.old_graph.nodes
        if node.kind == "Function"
    }
    assert any(
        alignment.old_node_id in old_functions
        and alignment.method == "EXACT_SEMANTIC_KEY"
        for alignment in refactor_delta.node_alignments
    )
