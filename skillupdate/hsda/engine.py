"""HSDA orchestration, fact differencing, indirect references, and raw audit diff."""

from __future__ import annotations

import difflib
import hashlib
import json
import time
from pathlib import Path

from .common import location, safe_relative_files, stable_id
from .javascript_analyzer import JavaScriptAnalyzer
from .markdown_analyzer import MarkdownAnalyzer
from .models import (
    AnalyzerIssue,
    AnalyzerResult,
    HSDAReport,
    RawFileDiff,
    SecurityEvidence,
    SemanticChange,
    SemanticFact,
    SnapshotSummary,
    SourceLocation,
)
from .python_analyzer import PythonAnalyzer
from .reference_analyzer import ReferenceAnalyzer
from .structured_analyzer import StructuredDataAnalyzer

MARKDOWN_SUFFIXES = {".md", ".markdown"}
JAVASCRIPT_SUFFIXES = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
YAML_SUFFIXES = {".yaml", ".yml"}


class SnapshotData:
    def __init__(
        self, root: Path, files: dict[str, str], hashes: dict[str, str]
    ) -> None:
        self.root = root
        self.files = files
        self.hashes = hashes
        canonical = "".join(f"{name}\0{hashes[name]}\n" for name in sorted(hashes))
        self.sha256 = hashlib.sha256(canonical.encode()).hexdigest()


def load_snapshot(
    root: str | Path, max_total_bytes: int = 8 * 1024 * 1024
) -> SnapshotData:
    path = Path(root).resolve()
    if not path.is_dir():
        raise ValueError(f"HSDA input is not a directory: {path}")
    files: dict[str, str] = {}
    hashes: dict[str, str] = {}
    total = 0
    for item in safe_relative_files(path):
        payload = item.read_bytes()
        total += len(payload)
        if total > max_total_bytes:
            raise ValueError("HSDA snapshot byte limit exceeded")
        relative = item.relative_to(path).as_posix()
        files[relative] = payload.decode("utf-8", errors="replace")
        hashes[relative] = hashlib.sha256(payload).hexdigest()
    return SnapshotData(path, files, hashes)


class HSDAAnalyzer:
    """Static heterogeneous analysis; it never calls an LLM or executes a Skill."""

    def __init__(self) -> None:
        self.markdown = MarkdownAnalyzer()
        self.python = PythonAnalyzer()
        self.javascript = JavaScriptAnalyzer()
        self.structured = StructuredDataAnalyzer()
        self.references = ReferenceAnalyzer()

    def analyze(
        self,
        old_skill_directory: str | Path,
        new_skill_directory: str | Path,
        output_dir: str | Path | None = None,
    ) -> HSDAReport:
        started = time.perf_counter()
        old = load_snapshot(old_skill_directory)
        new = load_snapshot(new_skill_directory)
        old_results = self._analyze_snapshot(old, "OLD")
        new_results = self._analyze_snapshot(new, "NEW")
        changes = self._diff_results(old_results, new_results)
        raw_diffs = self._raw_diffs(old, new)
        changes.extend(self._file_changes(old, new))
        changes.extend(
            self._indirect_reference_changes(old, new, old_results, new_results)
        )
        issues = [
            issue for result in old_results + new_results for issue in result.issues
        ]
        for raw in raw_diffs:
            if any(issue.file == raw.file for issue in issues):
                old_source = old.files.get(raw.file, "")
                new_source = new.files.get(raw.file, "")
                locations = self._file_endpoint_locations(
                    raw.file, old_source, new_source
                )
                changes.append(
                    SemanticChange(
                        change_id=stable_id("unknown", raw.file, raw.sha256),
                        dimension="CODE_BEHAVIOR",
                        change_type="UNKNOWN",
                        fact_kind="UNPARSED_CHANGED_FILE",
                        key=f"unknown:{raw.file}",
                        description=f"Changed file {raw.file} could not be completely parsed",
                        analyzer="dispatch",
                        certainty="UNKNOWN",
                        evidence=locations,
                        security_relevant=True,
                        risk_type="UNPARSED_CHANGED_FILE",
                    )
                )
        changes = self._deduplicate_changes(changes)
        security_evidence = [
            SecurityEvidence(
                evidence_id=stable_id("evidence", change.change_id),
                change_id=change.change_id,
                risk_type=change.risk_type or "SECURITY_RELEVANT_CHANGE",
                assertion=change.description,
                certainty=change.certainty,
                locations=change.evidence,
            )
            for change in changes
            if change.security_relevant
        ]
        grouped: dict[str, list[SemanticChange]] = {
            "STRUCTURE": [],
            "SEMANTIC": [],
            "PERMISSION": [],
            "CODE_BEHAVIOR": [],
            "REFERENCE": [],
        }
        unknown: list[SemanticChange] = []
        for change in changes:
            if change.certainty == "UNKNOWN" or change.change_type == "UNKNOWN":
                unknown.append(change)
            else:
                grouped[change.dimension].append(change)
        report = HSDAReport(
            old_snapshot=SnapshotSummary(
                root=str(old.root), sha256=old.sha256, file_count=len(old.files)
            ),
            new_snapshot=SnapshotSummary(
                root=str(new.root), sha256=new.sha256, file_count=len(new.files)
            ),
            structure_changes=grouped["STRUCTURE"],
            semantic_changes=grouped["SEMANTIC"],
            permission_changes=grouped["PERMISSION"],
            code_behavior_changes=grouped["CODE_BEHAVIOR"],
            reference_changes=grouped["REFERENCE"],
            security_evidence=security_evidence,
            unknown_changes=unknown,
            issues=issues,
            raw_diffs=raw_diffs,
            processing_time_ms=(time.perf_counter() - started) * 1000,
        )
        if output_dir is not None:
            self._save(report, Path(output_dir))
        return report

    def _analyze_snapshot(
        self, snapshot: SnapshotData, side: str
    ) -> list[AnalyzerResult]:
        results: list[AnalyzerResult] = []
        for file, source in sorted(snapshot.files.items()):
            suffix = Path(file).suffix.lower()
            if file == "SKILL.md" or suffix in MARKDOWN_SUFFIXES:
                results.append(self.markdown.analyze(file, source, side))
            elif suffix == ".py":
                results.append(self.python.analyze(file, source, side))
            elif suffix in JAVASCRIPT_SUFFIXES:
                results.append(self.javascript.analyze(file, source, side))
            elif suffix in YAML_SUFFIXES or suffix == ".json":
                results.append(self.structured.analyze(file, source, side))
            else:
                lines = source.splitlines()
                item_location = location(
                    snapshot=side,
                    file=file,
                    lines=lines,
                    start_line=1,
                    end_line=max(1, len(lines)),
                )
                results.append(
                    AnalyzerResult(
                        analyzer="unsupported",
                        facts=[
                            SemanticFact(
                                kind="PARSE_UNKNOWN",
                                key="unsupported-file",
                                value=hashlib.sha256(source.encode()).hexdigest(),
                                dimension="SEMANTIC",
                                location=item_location,
                                basis="STATIC_FILE_METADATA",
                                certainty="UNKNOWN",
                                security_relevant=True,
                                risk_type="UNSUPPORTED_FILE_TYPE",
                            )
                        ],
                        issues=[
                            AnalyzerIssue(
                                file=file,
                                analyzer="dispatch",
                                code="UNSUPPORTED_FILE_TYPE",
                                message=f"No P11 semantic analyzer for suffix {suffix or '<none>'}",
                                location=item_location,
                            )
                        ],
                    )
                )
        results.append(self.references.analyze_snapshot(snapshot.files, side))
        return results

    def _diff_results(
        self, old_results: list[AnalyzerResult], new_results: list[AnalyzerResult]
    ) -> list[SemanticChange]:
        old = self._fact_map(old_results)
        new = self._fact_map(new_results)
        changes: list[SemanticChange] = []
        for identity in sorted(set(old) | set(new)):
            before = old.get(identity)
            after = new.get(identity)
            if (
                before
                and after
                and before.value == after.value
                and before.attributes == after.attributes
            ):
                continue
            fact = after or before
            assert fact is not None
            if before is None:
                change_type = "ADDED"
            elif after is None:
                change_type = "REMOVED"
            else:
                change_type = "MODIFIED"
            certainty = (
                "UNKNOWN"
                if any(item and item.certainty == "UNKNOWN" for item in (before, after))
                else "FACT"
            )
            evidence = [item.location for item in (before, after) if item is not None]
            changes.append(
                SemanticChange(
                    change_id=stable_id(
                        *identity,
                        change_type,
                        before.value if before else "",
                        after.value if after else "",
                    ),
                    dimension=fact.dimension,
                    change_type="UNKNOWN" if certainty == "UNKNOWN" else change_type,
                    fact_kind=fact.kind,
                    key=fact.key,
                    before_value=before.value if before else None,
                    after_value=after.value if after else None,
                    description=f"{change_type.lower()} {fact.kind} in {fact.location.file}",
                    analyzer=fact.basis,
                    certainty=certainty,
                    evidence=evidence,
                    security_relevant=bool(
                        (before and before.security_relevant)
                        or (after and after.security_relevant)
                    ),
                    risk_type=(after.risk_type if after else None)
                    or (before.risk_type if before else None),
                )
            )
        return changes

    @staticmethod
    def _fact_map(
        results: list[AnalyzerResult],
    ) -> dict[tuple[str, str, str], SemanticFact]:
        mapped: dict[tuple[str, str, str], SemanticFact] = {}
        for result in results:
            for fact in result.facts:
                identity = (fact.location.file, fact.kind, fact.key)
                mapped[identity] = fact
        return mapped

    def _raw_diffs(self, old: SnapshotData, new: SnapshotData) -> list[RawFileDiff]:
        diffs: list[RawFileDiff] = []
        for file in sorted(set(old.files) | set(new.files)):
            before = old.files.get(file)
            after = new.files.get(file)
            if before == after:
                continue
            change_type = (
                "ADDED"
                if before is None
                else "REMOVED"
                if after is None
                else "MODIFIED"
            )
            unified = "".join(
                difflib.unified_diff(
                    (before or "").splitlines(keepends=True),
                    (after or "").splitlines(keepends=True),
                    fromfile=f"old/{file}",
                    tofile=f"new/{file}",
                    n=3,
                )
            )
            diffs.append(
                RawFileDiff(
                    file=file,
                    change_type=change_type,
                    unified_diff=unified,
                    sha256=hashlib.sha256(unified.encode()).hexdigest(),
                )
            )
        return diffs

    def _file_changes(
        self, old: SnapshotData, new: SnapshotData
    ) -> list[SemanticChange]:
        changes: list[SemanticChange] = []
        for file in sorted(set(old.files) ^ set(new.files)):
            added = file in new.files
            source = new.files[file] if added else old.files[file]
            side = "NEW" if added else "OLD"
            loc = location(
                snapshot=side,
                file=file,
                lines=source.splitlines(),
                start_line=1,
                end_line=max(1, len(source.splitlines())),
            )
            changes.append(
                SemanticChange(
                    change_id=stable_id("file", file, "added" if added else "removed"),
                    dimension="STRUCTURE",
                    change_type="ADDED" if added else "REMOVED",
                    fact_kind="FILE",
                    key=f"file:{file}",
                    before_value=None if added else file,
                    after_value=file if added else None,
                    description=f"{'added' if added else 'removed'} file {file}",
                    analyzer="dispatch",
                    certainty="FACT",
                    evidence=[loc],
                )
            )
        return changes

    def _indirect_reference_changes(
        self,
        old: SnapshotData,
        new: SnapshotData,
        old_results: list[AnalyzerResult],
        new_results: list[AnalyzerResult],
    ) -> list[SemanticChange]:
        changed_files = {
            file
            for file in set(old.files) | set(new.files)
            if old.files.get(file) != new.files.get(file)
        }
        changes: list[SemanticChange] = []
        for result in new_results:
            for fact in result.facts:
                if (
                    fact.basis != "STATIC_REFERENCE"
                    or fact.kind != "INTERNAL_REFERENCE"
                ):
                    continue
                target = str(fact.attributes.get("target", ""))
                if target not in changed_files or not fact.attributes.get("resolved"):
                    continue
                target_source = new.files[target]
                target_location = location(
                    snapshot="NEW",
                    file=target,
                    lines=target_source.splitlines(),
                    start_line=1,
                    end_line=max(1, len(target_source.splitlines())),
                )
                changes.append(
                    SemanticChange(
                        change_id=stable_id("indirect", fact.location.file, target),
                        dimension="REFERENCE",
                        change_type="MODIFIED",
                        fact_kind="INDIRECT_REFERENCE_CHANGE",
                        key=f"indirect:{fact.location.file}:{target}",
                        before_value=f"reference to old/{target}",
                        after_value=f"reference to new/{target}",
                        description=f"{fact.location.file} indirectly observes changes in referenced file {target}",
                        analyzer="STATIC_REFERENCE",
                        certainty="FACT",
                        evidence=[fact.location, target_location],
                        security_relevant=True,
                        risk_type="INDIRECT_INSTRUCTION_CHANGE",
                    )
                )
        return changes

    @staticmethod
    def _file_endpoint_locations(
        file: str, old_source: str, new_source: str
    ) -> list[SourceLocation]:
        locations: list[SourceLocation] = []
        for side, source in (("OLD", old_source), ("NEW", new_source)):
            if not source:
                continue
            lines = source.splitlines()
            locations.append(
                location(
                    snapshot=side,
                    file=file,
                    lines=lines,
                    start_line=1,
                    end_line=max(1, len(lines)),
                )
            )
        return locations

    @staticmethod
    def _deduplicate_changes(changes: list[SemanticChange]) -> list[SemanticChange]:
        unique: dict[str, SemanticChange] = {}
        for change in changes:
            unique[change.change_id] = change
        return [unique[key] for key in sorted(unique)]

    @staticmethod
    def _save(report: HSDAReport, output: Path) -> None:
        if output.exists():
            raise ValueError("HSDA output directory must not already exist")
        output.mkdir(parents=True)
        (output / "hsda_report.json").write_text(
            json.dumps(report.as_json(), ensure_ascii=False, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        combined = "\n".join(item.unified_diff for item in report.raw_diffs)
        (output / "raw.diff").write_text(combined, encoding="utf-8")
