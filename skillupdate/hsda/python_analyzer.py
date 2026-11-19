"""Python AST analysis preserving calls, operations, strings, and comments."""

from __future__ import annotations

import ast
import io
import tokenize

from .common import is_security_text, location, normalize_space
from .models import AnalyzerIssue, AnalyzerResult, SemanticFact

OPERATION_NAMES = {
    "FILE_OPERATION": {
        "open",
        "read_text",
        "read_bytes",
        "write_text",
        "write_bytes",
        "unlink",
        "remove",
        "rmtree",
    },
    "NETWORK_OPERATION": {
        "request",
        "urlopen",
        "get",
        "post",
        "send",
        "connect",
        "socket",
    },
    "PROCESS_OPERATION": {
        "system",
        "popen",
        "Popen",
        "run",
        "call",
        "check_call",
        "check_output",
        "execv",
        "spawn",
    },
}


def call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ast.dump(node, include_attributes=False)


class PythonAnalyzer:
    name = "python_ast"

    def analyze(self, file: str, source: str, snapshot: str) -> AnalyzerResult:
        lines = source.splitlines()
        try:
            tree = ast.parse(source, filename=file, type_comments=True)
        except SyntaxError as error:
            line_number = max(1, error.lineno or 1)
            issue_location = location(
                snapshot=snapshot, file=file, lines=lines, start_line=line_number
            )
            return AnalyzerResult(
                analyzer=self.name,
                issues=[
                    AnalyzerIssue(
                        file=file,
                        analyzer=self.name,
                        code="PYTHON_SYNTAX_ERROR",
                        message=error.msg,
                        location=issue_location,
                    )
                ],
                facts=[
                    SemanticFact(
                        kind="PARSE_UNKNOWN",
                        key="python-parse",
                        value=error.msg,
                        dimension="CODE_BEHAVIOR",
                        location=issue_location,
                        basis="STATIC_PYTHON_AST",
                        certainty="UNKNOWN",
                        security_relevant=True,
                        risk_type="UNPARSED_CODE",
                    )
                ],
            )
        facts: list[SemanticFact] = []
        call_ordinals: dict[str, int] = {}
        string_ordinal = 0
        for node in ast.walk(tree):
            start = getattr(node, "lineno", 1)
            end = getattr(node, "end_lineno", start)
            node_location = location(
                snapshot=snapshot,
                file=file,
                lines=lines,
                start_line=start,
                end_line=end,
            )
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                facts.append(
                    SemanticFact(
                        kind="FUNCTION_DEFINITION",
                        key=f"function:{node.name}",
                        value=f"{node.name}({ast.unparse(node.args)})",
                        dimension="STRUCTURE",
                        location=node_location,
                        basis="STATIC_PYTHON_AST",
                        attributes={"async": isinstance(node, ast.AsyncFunctionDef)},
                    )
                )
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                value = ast.unparse(node)
                facts.append(
                    SemanticFact(
                        kind="IMPORT",
                        key=f"import:{normalize_space(value)}",
                        value=value,
                        dimension="STRUCTURE",
                        location=node_location,
                        basis="STATIC_PYTHON_AST",
                    )
                )
            elif isinstance(node, ast.Call):
                target = call_name(node.func)
                ordinal = call_ordinals.get(target, 0)
                call_ordinals[target] = ordinal + 1
                value = ast.get_source_segment(source, node) or ast.unparse(node)
                risk_type = None
                for operation, names in OPERATION_NAMES.items():
                    if target.split(".")[-1] in names:
                        risk_type = operation
                        break
                security = risk_type is not None or is_security_text(value)
                facts.append(
                    SemanticFact(
                        kind="FUNCTION_CALL",
                        key=f"call:{target}:{ordinal}",
                        value=value,
                        dimension="CODE_BEHAVIOR",
                        location=node_location,
                        basis="STATIC_PYTHON_AST",
                        security_relevant=security,
                        risk_type=risk_type
                        or ("SECURITY_RELEVANT_CALL" if security else None),
                        attributes={"target": target},
                    )
                )
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                security = is_security_text(value)
                facts.append(
                    SemanticFact(
                        kind="STRING_LITERAL",
                        key=f"string:{string_ordinal}",
                        value=value,
                        dimension="SEMANTIC",
                        location=node_location,
                        basis="STATIC_PYTHON_AST",
                        security_relevant=security,
                        risk_type="SECURITY_RELEVANT_STRING" if security else None,
                    )
                )
                string_ordinal += 1
        try:
            comment_ordinal = 0
            for token in tokenize.generate_tokens(io.StringIO(source).readline):
                if token.type != tokenize.COMMENT:
                    continue
                value = token.string
                security = is_security_text(value)
                facts.append(
                    SemanticFact(
                        kind="COMMENT",
                        key=f"comment:{comment_ordinal}",
                        value=value,
                        dimension="SEMANTIC",
                        location=location(
                            snapshot=snapshot,
                            file=file,
                            lines=lines,
                            start_line=token.start[0],
                            end_line=token.end[0],
                        ),
                        basis="STATIC_PYTHON_AST",
                        security_relevant=security,
                        risk_type="SECURITY_RELEVANT_COMMENT" if security else None,
                    )
                )
                comment_ordinal += 1
        except tokenize.TokenError:
            pass
        return AnalyzerResult(analyzer=self.name, facts=facts)
