"""Markdown block, instruction, constraint, code-block, and link analysis."""

from __future__ import annotations

import re

from markdown_it import MarkdownIt

from .common import is_security_text, location, normalize_space
from .models import AnalyzerResult, SemanticFact

INSTRUCTION_PREFIX = re.compile(
    r"^(?:please\s+)?(?:do|use|call|run|read|write|send|collect|keep|process|validate|"
    r"return|create|remove|never|always|must|only|avoid|ensure|deny|allow)\b",
    re.IGNORECASE,
)
SECURITY_CONSTRAINT = re.compile(
    r"\b(?:must not|do not|never|only|deny|forbid|without|no\s+(?:network|command|credential))\b",
    re.IGNORECASE,
)


class MarkdownAnalyzer:
    name = "markdown"

    def analyze(self, file: str, source: str, snapshot: str) -> AnalyzerResult:
        lines = source.splitlines()
        tokens = MarkdownIt("commonmark").parse(source)
        facts: list[SemanticFact] = []
        counters: dict[str, int] = {}
        current_heading = "<root>"
        for index, token in enumerate(tokens):
            if token.type not in {
                "heading_open",
                "paragraph_open",
                "bullet_list_open",
                "ordered_list_open",
                "list_item_open",
                "fence",
                "code_block",
            }:
                continue
            start_zero, end_zero = token.map or (0, 1)
            start_line = start_zero + 1
            end_line = max(start_line, end_zero)
            content = token.content
            if token.type.endswith("_open") and index + 1 < len(tokens):
                inline = tokens[index + 1]
                if inline.type == "inline":
                    content = inline.content
            kind = {
                "heading_open": "MARKDOWN_HEADING",
                "paragraph_open": "MARKDOWN_PARAGRAPH",
                "bullet_list_open": "MARKDOWN_LIST",
                "ordered_list_open": "MARKDOWN_LIST",
                "list_item_open": "MARKDOWN_LIST_ITEM",
                "fence": "MARKDOWN_CODE_BLOCK",
                "code_block": "MARKDOWN_CODE_BLOCK",
            }[token.type]
            ordinal = counters.get(kind, 0)
            counters[kind] = ordinal + 1
            value = (
                normalize_space(content) if kind != "MARKDOWN_CODE_BLOCK" else content
            )
            if kind == "MARKDOWN_HEADING":
                current_heading = value
                value = f"level={token.tag.removeprefix('h')}:{value}"
            security = is_security_text(value)
            fact = SemanticFact(
                kind=kind,
                key=f"{kind}:{ordinal}",
                value=value,
                dimension="STRUCTURE",
                location=location(
                    snapshot=snapshot,
                    file=file,
                    lines=lines,
                    start_line=start_line,
                    end_line=end_line,
                ),
                basis="STATIC_MARKDOWN",
                security_relevant=security,
                risk_type="SECURITY_RELEVANT_TEXT" if security else None,
                attributes={
                    "heading_context": current_heading,
                    "token_type": token.type,
                },
            )
            facts.append(fact)
            if kind in {"MARKDOWN_PARAGRAPH", "MARKDOWN_LIST_ITEM"} and value:
                if INSTRUCTION_PREFIX.search(value):
                    facts.append(
                        SemanticFact(
                            kind="INSTRUCTION",
                            key=f"instruction:{kind}:{ordinal}",
                            value=value,
                            dimension="SEMANTIC",
                            location=fact.location,
                            basis="STATIC_MARKDOWN",
                            security_relevant=security,
                            risk_type="SECURITY_INSTRUCTION" if security else None,
                            attributes={"heading_context": current_heading},
                        )
                    )
                if SECURITY_CONSTRAINT.search(value):
                    facts.append(
                        SemanticFact(
                            kind="SECURITY_CONSTRAINT",
                            key=f"constraint:{kind}:{ordinal}",
                            value=value,
                            dimension="PERMISSION",
                            location=fact.location,
                            basis="STATIC_MARKDOWN",
                            security_relevant=True,
                            risk_type="SECURITY_CONSTRAINT",
                            attributes={"heading_context": current_heading},
                        )
                    )
        for ordinal, match in enumerate(re.finditer(r"\[([^]]+)\]\(([^)]+)\)", source)):
            line_number = source.count("\n", 0, match.start()) + 1
            target = match.group(2).strip()
            external = bool(re.match(r"^[a-z][a-z0-9+.-]*://", target, re.IGNORECASE))
            facts.append(
                SemanticFact(
                    kind="EXTERNAL_REFERENCE" if external else "INTERNAL_REFERENCE",
                    key=f"markdown-link:{ordinal}",
                    value=target,
                    dimension="REFERENCE",
                    location=location(
                        snapshot=snapshot,
                        file=file,
                        lines=lines,
                        start_line=line_number,
                    ),
                    basis="STATIC_MARKDOWN",
                    security_relevant=external,
                    risk_type="EXTERNAL_REFERENCE" if external else None,
                    attributes={"label": match.group(1)},
                )
            )
        for ordinal, match in enumerate(re.finditer(r"<!--[\s\S]*?-->", source)):
            line_number = source.count("\n", 0, match.start()) + 1
            end_line = line_number + match.group(0).count("\n")
            value = match.group(0)
            security = is_security_text(value)
            facts.append(
                SemanticFact(
                    kind="COMMENT",
                    key=f"html-comment:{ordinal}",
                    value=value,
                    dimension="SEMANTIC",
                    location=location(
                        snapshot=snapshot,
                        file=file,
                        lines=lines,
                        start_line=line_number,
                        end_line=end_line,
                    ),
                    basis="STATIC_MARKDOWN",
                    security_relevant=security,
                    risk_type="SECURITY_RELEVANT_COMMENT" if security else None,
                )
            )
        return AnalyzerResult(analyzer=self.name, facts=facts)
