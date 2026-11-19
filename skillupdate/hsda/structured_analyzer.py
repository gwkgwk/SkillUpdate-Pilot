"""Safe YAML/JSON field analysis with paths, line locations, and risk categories."""

from __future__ import annotations

import json
import re
from typing import Any

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from .common import is_security_text, location
from .models import AnalyzerIssue, AnalyzerResult, SemanticFact

PERMISSION_TERMS = {
    "permission",
    "permissions",
    "allow",
    "allowed",
    "deny",
    "network",
    "command",
    "readonly",
    "secret",
    "credential",
    "token",
}
ENDPOINT_TERMS = {"endpoint", "url", "uri", "host", "domain"}
DEPENDENCY_TERMS = {
    "dependency",
    "dependencies",
    "requirement",
    "requirements",
    "package",
    "packages",
}


def classify_path(path: str) -> tuple[str, str, bool, str | None]:
    tokens = set(re.split(r"[.\[\]_-]+", path.lower()))
    if tokens & PERMISSION_TERMS:
        return "PERMISSION_FIELD", "PERMISSION", True, "PERMISSION_CHANGE"
    if tokens & ENDPOINT_TERMS:
        return "ENDPOINT_FIELD", "PERMISSION", True, "ENDPOINT_CHANGE"
    if tokens & DEPENDENCY_TERMS:
        return "DEPENDENCY_FIELD", "SEMANTIC", True, "DEPENDENCY_CHANGE"
    return "CONFIG_FIELD", "SEMANTIC", False, None


class StructuredDataAnalyzer:
    name = "structured_data"

    def analyze(self, file: str, source: str, snapshot: str) -> AnalyzerResult:
        if file.lower().endswith(".json"):
            return self._json(file, source, snapshot)
        return self._yaml(file, source, snapshot)

    def _yaml(self, file: str, source: str, snapshot: str) -> AnalyzerResult:
        lines = source.splitlines()
        try:
            root = yaml.compose(source, Loader=yaml.SafeLoader)
        except yaml.YAMLError as error:
            return self._unknown(
                file, lines, snapshot, "YAML_PARSE_ERROR", str(error), "STATIC_YAML"
            )
        facts: list[SemanticFact] = []
        if root is not None:
            self._walk_yaml(root, "$", file, lines, snapshot, facts)
        comment_ordinal = 0
        for line_number, line in enumerate(lines, start=1):
            if "#" not in line:
                continue
            value = line[line.index("#") :]
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
                        start_line=line_number,
                    ),
                    basis="STATIC_YAML",
                    security_relevant=security,
                    risk_type="SECURITY_RELEVANT_COMMENT" if security else None,
                )
            )
            comment_ordinal += 1
        return AnalyzerResult(analyzer=self.name, facts=facts)

    def _walk_yaml(
        self,
        node: Node,
        path: str,
        file: str,
        lines: list[str],
        snapshot: str,
        facts: list[SemanticFact],
    ) -> None:
        if isinstance(node, MappingNode):
            for key_node, value_node in node.value:
                key = str(key_node.value)
                child_path = f"{path}.{key}"
                self._add_node_fact(
                    child_path, value_node, file, lines, snapshot, facts, "STATIC_YAML"
                )
                self._walk_yaml(value_node, child_path, file, lines, snapshot, facts)
        elif isinstance(node, SequenceNode):
            for index, child in enumerate(node.value):
                child_path = f"{path}[{index}]"
                self._add_node_fact(
                    child_path, child, file, lines, snapshot, facts, "STATIC_YAML"
                )
                self._walk_yaml(child, child_path, file, lines, snapshot, facts)

    def _add_node_fact(
        self,
        path: str,
        node: Node,
        file: str,
        lines: list[str],
        snapshot: str,
        facts: list[SemanticFact],
        basis: str,
    ) -> None:
        if isinstance(node, ScalarNode):
            value = str(node.value)
        elif isinstance(node, SequenceNode):
            value = f"sequence[{len(node.value)}]"
        elif isinstance(node, MappingNode):
            value = f"mapping[{len(node.value)}]"
        else:
            value = node.id
        kind, dimension, path_security, risk_type = classify_path(path)
        security = path_security or is_security_text(value)
        facts.append(
            SemanticFact(
                kind=kind,
                key=path,
                value=value,
                dimension=dimension,
                location=location(
                    snapshot=snapshot,
                    file=file,
                    lines=lines,
                    start_line=node.start_mark.line + 1,
                    end_line=max(node.start_mark.line + 1, node.end_mark.line + 1),
                ),
                basis=basis,
                security_relevant=security,
                risk_type=risk_type
                or ("SECURITY_RELEVANT_VALUE" if security else None),
            )
        )

    def _json(self, file: str, source: str, snapshot: str) -> AnalyzerResult:
        lines = source.splitlines()
        try:
            value = json.loads(source)
        except json.JSONDecodeError as error:
            return self._unknown(
                file,
                lines,
                snapshot,
                "JSON_PARSE_ERROR",
                error.msg,
                "STATIC_JSON",
                error.lineno,
            )
        facts: list[SemanticFact] = []
        key_occurrences: dict[str, list[int]] = {}
        for line_number, line in enumerate(lines, start=1):
            for match in re.finditer(r'"((?:\\.|[^"\\])+)"\s*:', line):
                key_occurrences.setdefault(
                    json.loads(f'"{match.group(1)}"'), []
                ).append(line_number)
        key_offsets: dict[str, int] = {}

        def walk(current: Any, path: str, line_hint: int = 1) -> None:
            if isinstance(current, dict):
                for key, child in current.items():
                    offset = key_offsets.get(key, 0)
                    candidates = key_occurrences.get(key, [line_hint])
                    line_number = candidates[min(offset, len(candidates) - 1)]
                    key_offsets[key] = offset + 1
                    child_path = f"{path}.{key}"
                    add(child_path, child, line_number)
                    walk(child, child_path, line_number)
            elif isinstance(current, list):
                for index, child in enumerate(current):
                    child_path = f"{path}[{index}]"
                    add(child_path, child, line_hint)
                    walk(child, child_path, line_hint)

        def add(path: str, current: Any, line_number: int) -> None:
            summary = (
                f"mapping[{len(current)}]"
                if isinstance(current, dict)
                else f"sequence[{len(current)}]"
                if isinstance(current, list)
                else json.dumps(current, ensure_ascii=False, sort_keys=True)
            )
            kind, dimension, path_security, risk_type = classify_path(path)
            security = path_security or is_security_text(summary)
            facts.append(
                SemanticFact(
                    kind=kind,
                    key=path,
                    value=summary,
                    dimension=dimension,
                    location=location(
                        snapshot=snapshot,
                        file=file,
                        lines=lines,
                        start_line=line_number,
                    ),
                    basis="STATIC_JSON",
                    security_relevant=security,
                    risk_type=risk_type
                    or ("SECURITY_RELEVANT_VALUE" if security else None),
                )
            )

        walk(value, "$")
        return AnalyzerResult(analyzer=self.name, facts=facts)

    def _unknown(
        self,
        file: str,
        lines: list[str],
        snapshot: str,
        code: str,
        message: str,
        basis: str,
        line_number: int = 1,
    ) -> AnalyzerResult:
        issue_location = location(
            snapshot=snapshot, file=file, lines=lines, start_line=line_number
        )
        return AnalyzerResult(
            analyzer=self.name,
            facts=[
                SemanticFact(
                    kind="PARSE_UNKNOWN",
                    key="structured-parse",
                    value=message,
                    dimension="SEMANTIC",
                    location=issue_location,
                    basis=basis,
                    certainty="UNKNOWN",
                    security_relevant=True,
                    risk_type="UNPARSED_CONFIGURATION",
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
