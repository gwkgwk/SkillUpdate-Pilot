from skillupdate.hsda.javascript_analyzer import JavaScriptAnalyzer


def test_javascript_uses_ast_and_preserves_security_comments_and_strings() -> None:
    source = """import fs from "node:fs";
// never expose credential tokens
export function run(url) {
  const secret = "credential-value";
  fs.readFileSync("synthetic.txt");
  fetch(url);
  child_process.exec("mock-command");
  return secret;
}
"""
    result = JavaScriptAnalyzer().analyze("scripts/main.js", source, "NEW")
    assert not result.issues
    assert any(fact.kind == "IMPORT" for fact in result.facts)
    assert any(
        fact.kind == "FUNCTION_DEFINITION" and "run" in fact.key
        for fact in result.facts
    )
    risks = {fact.risk_type for fact in result.facts if fact.risk_type}
    assert {"FILE_OPERATION", "NETWORK_OPERATION", "PROCESS_OPERATION"} <= risks
    assert any(
        fact.kind == "COMMENT" and fact.security_relevant for fact in result.facts
    )
    assert any(
        fact.kind == "STRING_LITERAL" and "credential-value" in fact.value
        for fact in result.facts
    )


def test_javascript_parse_failure_is_unknown() -> None:
    result = JavaScriptAnalyzer().analyze("broken.js", "function broken( {", "NEW")
    assert result.issues
    assert result.facts[0].certainty == "UNKNOWN"
