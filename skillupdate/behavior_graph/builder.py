"""Per-file behavioral graph fragments and global relation assembly."""

from __future__ import annotations

import ast
import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from skillupdate.hsda.common import stable_id
from skillupdate.hsda.engine import SnapshotData, load_snapshot
from skillupdate.hsda.javascript_analyzer import JavaScriptAnalyzer
from skillupdate.hsda.markdown_analyzer import MarkdownAnalyzer
from skillupdate.hsda.models import AnalyzerResult, SemanticFact, SourceLocation
from skillupdate.hsda.python_analyzer import PythonAnalyzer
from skillupdate.hsda.reference_analyzer import ReferenceAnalyzer
from skillupdate.hsda.structured_analyzer import StructuredDataAnalyzer

from .models import BehaviorEdge, BehaviorGraph, BehaviorNode, GraphEvidence

RISKY_TOOL_TAGS = {
    "FILE_OPERATION": "FILE_ACCESS",
    "NETWORK_OPERATION": "NETWORK_ACCESS",
    "PROCESS_OPERATION": "PROCESS_EXECUTION",
    "SECURITY_RELEVANT_CALL": "SECURITY_RELEVANT_CALL",
}
ENDPOINT_PATTERN = re.compile(r"(?:https?|mock)://[^\s'\")]+")
SENSITIVE_PATTERN = re.compile(
    r"\b(?:credential|secret|password|token|FAKE_[A-Z0-9_]+)\b", re.IGNORECASE
)


@dataclass
class GraphFragment:
    file: str
    content_sha256: str
    nodes: list[BehaviorNode]
    edges: list[BehaviorEdge]


def graph_evidence(
    location: SourceLocation, producer: str, basis: str = "STATIC_FACT"
) -> GraphEvidence:
    return GraphEvidence(
        snapshot=location.snapshot,
        file=location.file,
        start_line=location.start_line,
        end_line=location.end_line,
        excerpt=location.excerpt,
        basis=basis,
        producer=producer,
    )


def node_id(kind: str, semantic_key: str) -> str:
    return f"n-{stable_id(kind, semantic_key)}"


def edge_id(source_id: str, relation: str, target_id: str, semantic_key: str) -> str:
    return f"e-{stable_id(source_id, relation, target_id, semantic_key)}"


def make_node(
    kind: str,
    semantic_key: str,
    label: str,
    owner_file: str,
    evidence: list[GraphEvidence],
    *,
    basis: str = "STATIC_FACT",
    risk_tags: Iterable[str] = (),
    attributes: dict | None = None,
) -> BehaviorNode:
    return BehaviorNode(
        node_id=node_id(kind, semantic_key),
        kind=kind,
        semantic_key=semantic_key,
        label=label,
        owner_file=owner_file,
        basis=basis,
        evidence=evidence,
        risk_tags=sorted(set(risk_tags)),
        attributes=attributes or {},
    )


def make_edge(
    source: BehaviorNode,
    relation: str,
    target: BehaviorNode,
    semantic_key: str,
    evidence: list[GraphEvidence],
    *,
    basis: str = "STATIC_FACT",
    risk_tags: Iterable[str] = (),
    attributes: dict | None = None,
) -> BehaviorEdge:
    return BehaviorEdge(
        edge_id=edge_id(source.node_id, relation, target.node_id, semantic_key),
        source_id=source.node_id,
        target_id=target.node_id,
        relation=relation,
        semantic_key=semantic_key,
        owner_files=sorted({source.owner_file, target.owner_file}),
        basis=basis,
        evidence=evidence,
        risk_tags=sorted(set(risk_tags)),
        attributes=attributes or {},
    )


class BehavioralGraphBuilder:
    def __init__(self) -> None:
        self.markdown = MarkdownAnalyzer()
        self.python = PythonAnalyzer()
        self.javascript = JavaScriptAnalyzer()
        self.structured = StructuredDataAnalyzer()
        self.references = ReferenceAnalyzer()

    def snapshot(self, directory: str | Path) -> SnapshotData:
        return load_snapshot(directory)

    def build_fragments(
        self, snapshot: SnapshotData, side: str
    ) -> dict[str, GraphFragment]:
        return {
            file: self.build_fragment(file, source, snapshot.hashes[file], side)
            for file, source in sorted(snapshot.files.items())
        }

    def build_fragment(
        self, file: str, source: str, content_sha256: str, side: str
    ) -> GraphFragment:
        lines = source.splitlines()
        whole_location = SourceLocation(
            snapshot=side,
            file=file,
            start_line=1,
            end_line=max(1, len(lines)),
            excerpt="\n".join(lines[:20])[:2000],
        )
        file_node = make_node(
            "File",
            f"file:{file}",
            file,
            file,
            [graph_evidence(whole_location, "file_inventory")],
            attributes={
                "content_sha256": content_sha256,
                "suffix": Path(file).suffix.lower(),
            },
        )
        nodes = [file_node]
        edges: list[BehaviorEdge] = []
        result = self._analyze_file(file, source, side)
        function_nodes: list[BehaviorNode] = []
        for fact in result.facts:
            evidence = [graph_evidence(fact.location, fact.basis)]
            if fact.kind == "INSTRUCTION":
                instruction = make_node(
                    "Instruction",
                    f"instruction:{file}:{fact.key}",
                    fact.value,
                    file,
                    evidence,
                    risk_tags=[fact.risk_type] if fact.risk_type else [],
                    attributes={
                        "heading_context": fact.attributes.get("heading_context")
                    },
                )
                nodes.append(instruction)
                edges.append(
                    make_edge(
                        instruction,
                        "INSTRUCTS",
                        file_node,
                        f"instruction-file:{fact.key}",
                        evidence,
                    )
                )
                if not self._is_negative_constraint(fact.value):
                    self._instruction_capabilities(instruction, fact, nodes, edges)
            elif fact.kind == "SECURITY_CONSTRAINT":
                permission = make_node(
                    "Permission",
                    f"permission:{file}:{fact.key}",
                    fact.value,
                    file,
                    evidence,
                    risk_tags=["SECURITY_CONSTRAINT"],
                    attributes={"effect": "DENY"},
                )
                nodes.append(permission)
                edges.append(
                    make_edge(
                        file_node,
                        "REFERENCES",
                        permission,
                        f"file-permission:{fact.key}",
                        evidence,
                    )
                )
            elif fact.kind == "FUNCTION_DEFINITION":
                fingerprint = self._function_fingerprint(fact.location.excerpt, file)
                function = make_node(
                    "Function",
                    f"function:{file}:{fact.key.removeprefix('function:')}",
                    fact.value,
                    file,
                    evidence,
                    attributes={
                        "name": fact.key.removeprefix("function:"),
                        "structure_fingerprint": fingerprint,
                    },
                )
                nodes.append(function)
                function_nodes.append(function)
                edges.append(
                    make_edge(
                        file_node,
                        "REFERENCES",
                        function,
                        f"declares:{function.semantic_key}",
                        evidence,
                    )
                )
            elif fact.kind == "FUNCTION_CALL":
                caller = (
                    self._enclosing_function(function_nodes, fact.location.start_line)
                    or file_node
                )
                target_name = str(fact.attributes.get("target", fact.key)).split(".")[
                    -1
                ]
                inferred_risk_type = fact.risk_type or self._risk_type_from_name(
                    target_name
                )
                risk_tag = RISKY_TOOL_TAGS.get(inferred_risk_type or "")
                tool = make_node(
                    "Tool",
                    f"tool:{target_name}",
                    target_name,
                    file,
                    evidence,
                    risk_tags=[risk_tag] if risk_tag else [],
                    attributes={"call_target": target_name},
                )
                nodes.append(tool)
                edges.append(
                    make_edge(
                        caller,
                        "INVOKES",
                        tool,
                        f"call:{file}:{fact.key}",
                        evidence,
                        risk_tags=[risk_tag] if risk_tag else [],
                        attributes={"call_target": target_name},
                    )
                )
                operation_fact = fact.model_copy(
                    update={"risk_type": inferred_risk_type}
                )
                self._operation_nodes(caller, operation_fact, nodes, edges)
            elif fact.kind == "STRING_LITERAL":
                caller = (
                    self._enclosing_function(function_nodes, fact.location.start_line)
                    or file_node
                )
                self._literal_nodes(caller, fact, nodes, edges)
            elif fact.kind in {
                "PERMISSION_FIELD",
                "ENDPOINT_FIELD",
                "DEPENDENCY_FIELD",
            }:
                self._configuration_nodes(file_node, fact, nodes, edges)
        return GraphFragment(
            file=file,
            content_sha256=content_sha256,
            nodes=self._unique_nodes(nodes),
            edges=self._unique_edges(edges),
        )

    def assemble(
        self,
        snapshot: SnapshotData,
        fragments: dict[str, GraphFragment],
        side: str,
    ) -> BehaviorGraph:
        nodes = self._unique_nodes(
            node for fragment in fragments.values() for node in fragment.nodes
        )
        node_by_id = {node.node_id: node for node in nodes}
        edges = self._unique_edges(
            edge for fragment in fragments.values() for edge in fragment.edges
        )
        file_nodes = {node.owner_file: node for node in nodes if node.kind == "File"}
        function_by_name: dict[str, list[BehaviorNode]] = {}
        for node in nodes:
            if node.kind == "Function":
                function_by_name.setdefault(
                    str(node.attributes.get("name", "")), []
                ).append(node)
        rebuilt: list[BehaviorEdge] = []
        for edge in edges:
            if edge.relation != "INVOKES":
                rebuilt.append(edge)
                continue
            target = node_by_id[edge.target_id]
            call_target = str(target.attributes.get("call_target", ""))
            matches = function_by_name.get(call_target, [])
            if len(matches) == 1:
                source = node_by_id[edge.source_id]
                rebuilt.append(
                    make_edge(
                        source,
                        "CALLS",
                        matches[0],
                        f"resolved-call:{edge.semantic_key}",
                        edge.evidence,
                        basis="RULE_INFERENCE",
                        attributes={"resolution": "unique_function_name"},
                    )
                )
            else:
                rebuilt.append(edge)
        reference_result = self.references.analyze_snapshot(snapshot.files, side)
        for fact in reference_result.facts:
            source = file_nodes.get(fact.location.file)
            if source is None:
                continue
            evidence = [graph_evidence(fact.location, "reference_analyzer")]
            if fact.kind == "INTERNAL_REFERENCE":
                target = file_nodes.get(str(fact.attributes.get("target")))
                if target is not None:
                    rebuilt.append(
                        make_edge(
                            source,
                            "REFERENCES",
                            target,
                            f"reference:{source.owner_file}:{target.owner_file}",
                            evidence,
                        )
                    )
            else:
                target_value = str(fact.attributes.get("target", fact.value))
                endpoint = make_node(
                    "Endpoint",
                    f"endpoint:{target_value}",
                    target_value,
                    source.owner_file,
                    evidence,
                    risk_tags=["EXTERNAL_ENDPOINT"]
                    if target_value.startswith(("http://", "https://"))
                    else ["SIMULATED_ENDPOINT"],
                )
                nodes = self._unique_nodes([*nodes, endpoint])
                rebuilt.append(
                    make_edge(
                        source,
                        "CONNECTS_TO",
                        endpoint,
                        f"endpoint-reference:{source.owner_file}:{target_value}",
                        evidence,
                    )
                )
        rebuilt.extend(self._python_import_edges(snapshot, file_nodes, side))
        nodes = self._unique_nodes(nodes)
        return BehaviorGraph(
            snapshot_id=f"{side.lower()}:{snapshot.sha256[:16]}",
            snapshot_sha256=snapshot.sha256,
            nodes=sorted(nodes, key=lambda item: item.node_id),
            edges=sorted(self._unique_edges(rebuilt), key=lambda item: item.edge_id),
        )

    def reuse_fragment(self, fragment: GraphFragment) -> GraphFragment:
        def new_evidence(items: list[GraphEvidence]) -> list[GraphEvidence]:
            return [item.model_copy(update={"snapshot": "NEW"}) for item in items]

        nodes = [
            node.model_copy(update={"evidence": new_evidence(node.evidence)})
            for node in fragment.nodes
        ]
        edges = [
            edge.model_copy(update={"evidence": new_evidence(edge.evidence)})
            for edge in fragment.edges
        ]
        return GraphFragment(fragment.file, fragment.content_sha256, nodes, edges)

    def _analyze_file(self, file: str, source: str, side: str) -> AnalyzerResult:
        suffix = Path(file).suffix.lower()
        if file == "SKILL.md" or suffix in {".md", ".markdown"}:
            return self.markdown.analyze(file, source, side)
        if suffix == ".py":
            return self.python.analyze(file, source, side)
        if suffix in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}:
            return self.javascript.analyze(file, source, side)
        if suffix in {".yaml", ".yml", ".json"}:
            return self.structured.analyze(file, source, side)
        return AnalyzerResult(analyzer="unsupported")

    def _instruction_capabilities(
        self,
        instruction: BehaviorNode,
        fact: SemanticFact,
        nodes: list[BehaviorNode],
        edges: list[BehaviorEdge],
    ) -> None:
        lower = fact.value.lower()
        evidence = instruction.evidence
        capabilities: list[tuple[str, str, str, list[str]]] = []
        if any(word in lower for word in ("send", "transmit", "upload", "endpoint")):
            capabilities.append(
                (
                    "Tool",
                    "tool:data-transmission",
                    "data transmission",
                    ["DATA_TRANSMISSION"],
                )
            )
        if any(word in lower for word in ("command", "execute", "run shell")):
            capabilities.append(
                (
                    "Tool",
                    "tool:process-execution",
                    "process execution",
                    ["PROCESS_EXECUTION"],
                )
            )
        if SENSITIVE_PATTERN.search(fact.value):
            capabilities.append(
                ("Data", "data:sensitive", "sensitive data", ["SENSITIVE_DATA"])
            )
        for value in ENDPOINT_PATTERN.findall(fact.value):
            capabilities.append(
                (
                    "Endpoint",
                    f"endpoint:{value}",
                    value,
                    [
                        "EXTERNAL_ENDPOINT"
                        if value.startswith("http")
                        else "SIMULATED_ENDPOINT"
                    ],
                )
            )
        for kind, key, label, tags in capabilities:
            target = make_node(
                kind,
                key,
                label,
                instruction.owner_file,
                evidence,
                basis="RULE_INFERENCE",
                risk_tags=tags,
            )
            nodes.append(target)
            edges.append(
                make_edge(
                    instruction,
                    "INSTRUCTS",
                    target,
                    f"instruction-capability:{instruction.semantic_key}:{key}",
                    evidence,
                    basis="RULE_INFERENCE",
                    risk_tags=tags,
                )
            )

    def _operation_nodes(
        self,
        caller: BehaviorNode,
        fact: SemanticFact,
        nodes: list[BehaviorNode],
        edges: list[BehaviorEdge],
    ) -> None:
        evidence = [graph_evidence(fact.location, fact.basis)]
        if fact.risk_type == "FILE_OPERATION":
            data = make_node(
                "Data",
                f"data:file:{caller.owner_file}:{fact.key}",
                fact.value,
                caller.owner_file,
                evidence,
                risk_tags=["FILE_DATA"],
            )
            nodes.append(data)
            relation = (
                "WRITES"
                if any(word in fact.value for word in ("write", "unlink", "remove"))
                else "READS"
            )
            edges.append(
                make_edge(
                    caller, relation, data, f"file-operation:{fact.key}", evidence
                )
            )
        if fact.risk_type == "NETWORK_OPERATION":
            endpoints = ENDPOINT_PATTERN.findall(fact.value) or ["<dynamic-endpoint>"]
            for value in endpoints:
                endpoint = make_node(
                    "Endpoint",
                    f"endpoint:{caller.owner_file}:{value}",
                    value,
                    caller.owner_file,
                    evidence,
                    risk_tags=[
                        "DYNAMIC_ENDPOINT"
                        if value.startswith("<")
                        else "NETWORK_ENDPOINT"
                    ],
                )
                nodes.append(endpoint)
                edges.append(
                    make_edge(
                        caller,
                        "CONNECTS_TO",
                        endpoint,
                        f"network-operation:{fact.key}:{value}",
                        evidence,
                        risk_tags=["NETWORK_ACCESS"],
                    )
                )

    def _literal_nodes(
        self,
        caller: BehaviorNode,
        fact: SemanticFact,
        nodes: list[BehaviorNode],
        edges: list[BehaviorEdge],
    ) -> None:
        evidence = [graph_evidence(fact.location, fact.basis)]
        if SENSITIVE_PATTERN.search(fact.value):
            data = make_node(
                "Data",
                f"data:sensitive:{caller.owner_file}:{fact.key}",
                fact.value,
                caller.owner_file,
                evidence,
                risk_tags=["SENSITIVE_DATA"],
            )
            nodes.append(data)
            edges.append(
                make_edge(
                    caller, "READS", data, f"sensitive-literal:{fact.key}", evidence
                )
            )
        for value in ENDPOINT_PATTERN.findall(fact.value):
            endpoint = make_node(
                "Endpoint",
                f"endpoint:{caller.owner_file}:{value}",
                value,
                caller.owner_file,
                evidence,
                risk_tags=[
                    "NETWORK_ENDPOINT"
                    if value.startswith("http")
                    else "SIMULATED_ENDPOINT"
                ],
            )
            nodes.append(endpoint)
            edges.append(
                make_edge(
                    caller,
                    "CONNECTS_TO",
                    endpoint,
                    f"endpoint-literal:{fact.key}:{value}",
                    evidence,
                )
            )

    def _configuration_nodes(
        self,
        file_node: BehaviorNode,
        fact: SemanticFact,
        nodes: list[BehaviorNode],
        edges: list[BehaviorEdge],
    ) -> None:
        evidence = [graph_evidence(fact.location, fact.basis)]
        if fact.kind == "PERMISSION_FIELD":
            permission = make_node(
                "Permission",
                f"permission:{file_node.owner_file}:{fact.key}",
                f"{fact.key}={fact.value}",
                file_node.owner_file,
                evidence,
                risk_tags=["PERMISSION_ALLOW"]
                if fact.value.lower() in {"allow", "true", "enabled"}
                else ["PERMISSION_DENY"],
                attributes={"value": fact.value},
            )
            nodes.append(permission)
            edges.append(
                make_edge(
                    file_node,
                    "REFERENCES",
                    permission,
                    f"config-permission:{fact.key}",
                    evidence,
                )
            )
            if "PERMISSION_ALLOW" in permission.risk_tags:
                tool = make_node(
                    "Tool",
                    "tool:granted-capability",
                    "granted capability",
                    file_node.owner_file,
                    evidence,
                    basis="RULE_INFERENCE",
                    risk_tags=["GRANTED_CAPABILITY"],
                )
                nodes.append(tool)
                edges.append(
                    make_edge(
                        permission,
                        "GRANTS",
                        tool,
                        f"permission-grant:{fact.key}",
                        evidence,
                        basis="RULE_INFERENCE",
                        risk_tags=["PERMISSION_ENABLEMENT"],
                    )
                )
        elif fact.kind == "ENDPOINT_FIELD":
            endpoint = make_node(
                "Endpoint",
                f"endpoint:{file_node.owner_file}:{fact.value}",
                fact.value,
                file_node.owner_file,
                evidence,
                risk_tags=["CONFIGURED_ENDPOINT"],
            )
            nodes.append(endpoint)
            edges.append(
                make_edge(
                    file_node,
                    "CONNECTS_TO",
                    endpoint,
                    f"config-endpoint:{fact.key}",
                    evidence,
                )
            )
        elif fact.kind == "DEPENDENCY_FIELD":
            tool = make_node(
                "Tool",
                f"tool:dependency:{fact.value}",
                fact.value,
                file_node.owner_file,
                evidence,
                risk_tags=["DEPENDENCY"],
            )
            nodes.append(tool)
            edges.append(
                make_edge(
                    file_node, "INVOKES", tool, f"dependency:{fact.key}", evidence
                )
            )

    def _python_import_edges(
        self, snapshot: SnapshotData, file_nodes: dict[str, BehaviorNode], side: str
    ) -> list[BehaviorEdge]:
        edges: list[BehaviorEdge] = []
        for file, source in snapshot.files.items():
            if not file.endswith(".py") or file not in file_nodes:
                continue
            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue
            lines = source.splitlines()
            for node in ast.walk(tree):
                if (
                    not isinstance(node, ast.ImportFrom)
                    or node.level <= 0
                    or not node.module
                ):
                    continue
                candidate = (
                    PurePosixPath(file).parent / f"{node.module.replace('.', '/')}.py"
                )
                target = file_nodes.get(candidate.as_posix())
                if target is None:
                    continue
                evidence = GraphEvidence(
                    snapshot=side,
                    file=file,
                    start_line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno),
                    excerpt=lines[node.lineno - 1],
                    basis="STATIC_FACT",
                    producer="python_ast_import",
                )
                edges.append(
                    make_edge(
                        file_nodes[file],
                        "REFERENCES",
                        target,
                        f"python-import:{file}:{target.owner_file}",
                        [evidence],
                    )
                )
        return edges

    @staticmethod
    def _enclosing_function(
        functions: list[BehaviorNode], line: int
    ) -> BehaviorNode | None:
        candidates = [
            node
            for node in functions
            if node.evidence[0].start_line <= line <= node.evidence[0].end_line
        ]
        return (
            min(
                candidates,
                key=lambda node: (
                    node.evidence[0].end_line - node.evidence[0].start_line
                ),
            )
            if candidates
            else None
        )

    @staticmethod
    def _function_fingerprint(source: str, file: str) -> str:
        if file.endswith(".py"):
            try:
                tree = ast.parse(source)
                function = tree.body[0]
                if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    function.name = "_FUNCTION_"
                return hashlib.sha256(
                    ast.dump(function, include_attributes=False).encode()
                ).hexdigest()
            except (SyntaxError, IndexError):
                pass
        normalized = re.sub(
            r"\b(?:function\s+)?[A-Za-z_$][\w$]*\s*(?=\()",
            "_FUNCTION_",
            source,
            count=1,
        )
        return hashlib.sha256(" ".join(normalized.split()).encode()).hexdigest()

    @staticmethod
    def _risk_type_from_name(target_name: str) -> str | None:
        lower = target_name.lower()
        if any(
            token in lower
            for token in ("send", "transmit", "upload", "fetch", "request", "connect")
        ):
            return "NETWORK_OPERATION"
        if any(
            token in lower for token in ("execute", "exec", "spawn", "system", "popen")
        ):
            return "PROCESS_OPERATION"
        if any(
            token in lower
            for token in ("read", "open", "load", "write", "unlink", "remove")
        ):
            return "FILE_OPERATION"
        return None

    @staticmethod
    def _is_negative_constraint(value: str) -> bool:
        lower = value.lower()
        return any(
            marker in lower
            for marker in (
                "do not",
                "must not",
                "never",
                "deny",
                "forbid",
                "without permission",
                "no network",
                "no command",
            )
        )

    @staticmethod
    def _unique_nodes(nodes: Iterable[BehaviorNode]) -> list[BehaviorNode]:
        unique: dict[str, BehaviorNode] = {}
        for node in nodes:
            if node.node_id not in unique:
                unique[node.node_id] = node
            else:
                current = unique[node.node_id]
                evidence = {
                    item.model_dump_json(): item
                    for item in current.evidence + node.evidence
                }
                unique[node.node_id] = current.model_copy(
                    update={
                        "evidence": list(evidence.values()),
                        "risk_tags": sorted(
                            set(current.risk_tags) | set(node.risk_tags)
                        ),
                    }
                )
        return list(unique.values())

    @staticmethod
    def _unique_edges(edges: Iterable[BehaviorEdge]) -> list[BehaviorEdge]:
        unique: dict[str, BehaviorEdge] = {}
        for edge in edges:
            if edge.edge_id not in unique:
                unique[edge.edge_id] = edge
            else:
                current = unique[edge.edge_id]
                evidence = {
                    item.model_dump_json(): item
                    for item in current.evidence + edge.evidence
                }
                unique[edge.edge_id] = current.model_copy(
                    update={
                        "evidence": list(evidence.values()),
                        "risk_tags": sorted(
                            set(current.risk_tags) | set(edge.risk_tags)
                        ),
                    }
                )
        return list(unique.values())
