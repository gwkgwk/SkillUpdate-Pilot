"""Internal/external reference extraction and resolution across a Skill snapshot."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from .common import location
from .models import AnalyzerResult, SemanticFact

PATH_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_.-])((?:scripts|references|config|assets)/[A-Za-z0-9_./-]+)"
)
URL_PATTERN = re.compile(r"\b(?:https?|mock)://[^\s)>'\"]+")


class ReferenceAnalyzer:
    name = "references"

    def analyze_snapshot(self, files: dict[str, str], snapshot: str) -> AnalyzerResult:
        facts: list[SemanticFact] = []
        for file, source in sorted(files.items()):
            lines = source.splitlines()
            ordinal = 0
            seen: set[tuple[int, str]] = set()
            for pattern, external in ((PATH_PATTERN, False), (URL_PATTERN, True)):
                for match in pattern.finditer(source):
                    target = match.group(1) if not external else match.group(0)
                    line_number = source.count("\n", 0, match.start()) + 1
                    marker = (line_number, target)
                    if marker in seen:
                        continue
                    seen.add(marker)
                    resolved = None
                    if not external:
                        normalized = PurePosixPath(target).as_posix()
                        resolved = normalized in files
                    facts.append(
                        SemanticFact(
                            kind="EXTERNAL_REFERENCE"
                            if external
                            else "INTERNAL_REFERENCE",
                            key=f"reference:{ordinal}",
                            value=target,
                            dimension="REFERENCE",
                            location=location(
                                snapshot=snapshot,
                                file=file,
                                lines=lines,
                                start_line=line_number,
                            ),
                            basis="STATIC_REFERENCE",
                            security_relevant=external or resolved is False,
                            risk_type=(
                                "EXTERNAL_REFERENCE"
                                if external
                                else "UNRESOLVED_INTERNAL_REFERENCE"
                                if resolved is False
                                else None
                            ),
                            attributes={
                                "target": target,
                                "external": external,
                                "resolved": resolved,
                            },
                        )
                    )
                    ordinal += 1
        return AnalyzerResult(analyzer=self.name, facts=facts)
