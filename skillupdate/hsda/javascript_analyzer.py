"""JavaScript/TypeScript AST analysis through the pinned local Babel parser."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .common import is_security_text, location
from .models import AnalyzerIssue, AnalyzerResult, SemanticFact

OPERATION_NAMES = {
    "FILE_OPERATION": {
        "readFile",
        "readFileSync",
        "writeFile",
        "writeFileSync",
        "unlink",
        "rm",
    },
    "NETWORK_OPERATION": {"fetch", "request", "get", "post", "connect", "send"},
    "PROCESS_OPERATION": {"exec", "execFile", "spawn", "fork"},
}


class JavaScriptAnalyzer:
    name = "javascript_ast"

    def __init__(self, project_root: Path | None = None) -> None:
        self.project_root = project_root or Path(__file__).resolve().parents[2]
        self.parser = (
            self.project_root
            / "config/javascript/node_modules/@babel/parser"
        )
        self.bridge = Path(__file__).with_name("js_ast_parser.mjs")
        self.node = shutil.which("node")

    def analyze(self, file: str, source: str, snapshot: str) -> AnalyzerResult:
        lines = source.splitlines()
        if len(source.encode()) > 1024 * 1024:
            return self._unknown(
                file, lines, snapshot, "JAVASCRIPT_SIZE_LIMIT", "source exceeds 1 MiB"
            )
        if not self.node or not self.parser.is_dir():
            return self._unknown(
                file,
                lines,
                snapshot,
                "JAVASCRIPT_PARSER_UNAVAILABLE",
                "pinned Babel parser unavailable",
            )
        try:
            completed = subprocess.run(
                [
                    self.node,
                    "--max-old-space-size=128",
                    str(self.bridge),
                    str(self.parser),
                ],
                input=json.dumps({"filename": file, "source": source}),
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
                env={"PATH": str(Path(self.node).parent), "LANG": "C.UTF-8"},
            )
        except subprocess.TimeoutExpired:
            return self._unknown(
                file,
                lines,
                snapshot,
                "JAVASCRIPT_PARSE_TIMEOUT",
                "Babel parser timed out",
            )
        if completed.returncode:
            message = (
                completed.stderr.strip().splitlines()[-1][:1000]
                if completed.stderr.strip()
                else "Babel parse failed"
            )
            return self._unknown(
                file, lines, snapshot, "JAVASCRIPT_SYNTAX_ERROR", message
            )
        payload = json.loads(completed.stdout)
        facts: list[SemanticFact] = []
        for item in payload["facts"]:
            kind = item["kind"]
            value = item["value"]
            dimension = (
                "STRUCTURE"
                if kind in {"IMPORT", "FUNCTION_DEFINITION"}
                else "SEMANTIC"
                if kind in {"STRING_LITERAL", "COMMENT"}
                else "CODE_BEHAVIOR"
            )
            risk_type = None
            target = item.get("attributes", {}).get("target", "").split(".")[-1]
            for operation, names in OPERATION_NAMES.items():
                if target in names:
                    risk_type = operation
                    break
            security = risk_type is not None or is_security_text(value)
            facts.append(
                SemanticFact(
                    kind=kind,
                    key=item["key"],
                    value=value,
                    dimension=dimension,
                    location=location(
                        snapshot=snapshot,
                        file=file,
                        lines=lines,
                        start_line=item["start_line"],
                        end_line=item["end_line"],
                    ),
                    basis="STATIC_JAVASCRIPT_AST",
                    security_relevant=security,
                    risk_type=risk_type
                    or ("SECURITY_RELEVANT_TEXT" if security else None),
                    attributes=item.get("attributes", {}),
                )
            )
        return AnalyzerResult(analyzer=self.name, facts=facts)

    def _unknown(
        self, file: str, lines: list[str], snapshot: str, code: str, message: str
    ) -> AnalyzerResult:
        issue_location = location(
            snapshot=snapshot,
            file=file,
            lines=lines,
            start_line=1,
            end_line=max(1, len(lines)),
        )
        return AnalyzerResult(
            analyzer=self.name,
            facts=[
                SemanticFact(
                    kind="PARSE_UNKNOWN",
                    key="javascript-parse",
                    value=message,
                    dimension="CODE_BEHAVIOR",
                    location=issue_location,
                    basis="STATIC_JAVASCRIPT_AST",
                    certainty="UNKNOWN",
                    security_relevant=True,
                    risk_type="UNPARSED_CODE",
                )
            ],
            issues=[
                AnalyzerIssue(
                    file=file,
                    analyzer=self.name,
                    code=code,
                    message=message,
                    location=issue_location,
                )
            ],
        )
