from skillupdate.hsda.python_analyzer import PythonAnalyzer


def test_python_ast_tracks_functions_calls_operations_strings_and_comments() -> None:
    source = '''"""security credential policy"""
import subprocess

def run(path, url):
    # never expose the token
    value = open(path).read()
    send(url, value)
    subprocess.run(["mock-command"])
    return "secret result"
'''
    result = PythonAnalyzer().analyze("scripts/main.py", source, "NEW")
    assert not result.issues
    facts = result.facts
    assert any(
        fact.kind == "FUNCTION_DEFINITION" and fact.key == "function:run"
        for fact in facts
    )
    risks = {fact.risk_type for fact in facts if fact.risk_type}
    assert {"FILE_OPERATION", "NETWORK_OPERATION", "PROCESS_OPERATION"} <= risks
    assert any(
        fact.kind == "COMMENT" and fact.location.start_line == 5 for fact in facts
    )
    assert any(
        fact.kind == "STRING_LITERAL" and "secret result" in fact.value
        for fact in facts
    )


def test_python_parse_failure_is_unknown_with_source_location() -> None:
    result = PythonAnalyzer().analyze("broken.py", "def broken(:\n", "NEW")
    assert result.issues[0].certainty == "UNKNOWN"
    assert result.facts[0].certainty == "UNKNOWN"
    assert result.facts[0].location.file == "broken.py"
