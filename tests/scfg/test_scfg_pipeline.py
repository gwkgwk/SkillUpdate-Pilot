from skillupdate.behavior_graph.models import BehaviorEdge, BehaviorGraph, BehaviorNode, GraphEvidence
from skillupdate.capability import CapabilityAnalyzer
from skillupdate.scfg import SCFGBuilder, SCFGIncrementalAnalyzer, SCFGPathAnalyzer


def evidence(side, line):
    return GraphEvidence(
        snapshot=side, file="scripts/main.py", start_line=line, end_line=line,
        excerpt=f"evidence line {line}", basis="STATIC_FACT", producer="test",
    )


def make_graph(side="NEW", endpoint=True):
    nodes = [
        BehaviorNode(
            node_id="data", kind="Data", semantic_key="data:credential",
            label="credential token", owner_file="scripts/main.py",
            basis="STATIC_FACT", evidence=[evidence(side, 1)],
            risk_tags=["SENSITIVE_DATA"], attributes={"sensitive": True},
        ),
        BehaviorNode(
            node_id="function", kind="Function", semantic_key="function:send",
            label="send", owner_file="scripts/main.py",
            basis="STATIC_FACT", evidence=[evidence(side, 2)],
        ),
    ]
    edges = [
        BehaviorEdge(
            edge_id="read", source_id="function", target_id="data",
            relation="READS", semantic_key="reads-credential",
            owner_files=["scripts/main.py"], basis="RULE_INFERENCE",
            evidence=[evidence(side, 3)],
        )
    ]
    if endpoint:
        nodes.append(
            BehaviorNode(
                node_id="endpoint", kind="Endpoint", semantic_key="endpoint:external",
                label="external endpoint", owner_file="scripts/main.py",
                basis="STATIC_FACT", evidence=[evidence(side, 4)],
                risk_tags=["EXTERNAL_ENDPOINT"], attributes={"external": True},
            )
        )
        edges.append(
            BehaviorEdge(
                edge_id="network", source_id="function", target_id="endpoint",
                relation="CONNECTS_TO", semantic_key="connect-external",
                owner_files=["scripts/main.py"], basis="RULE_INFERENCE",
                evidence=[evidence(side, 5)],
            )
        )
    return BehaviorGraph(
        snapshot_id=f"{side.lower()}-graph", snapshot_sha256="a" * 64,
        nodes=nodes, edges=edges,
    )


def build_scfg(graph):
    capabilities = CapabilityAnalyzer().analyze(graph)
    return SCFGBuilder().build(graph, capabilities)


def test_sensitive_data_path_crosses_external_trust_boundary():
    graph = make_graph(endpoint=True)
    scfg = build_scfg(graph)
    assert any(edge.relation == "FUNCTION_SCOPE_MAY_FLOW" for edge in scfg.edges)
    assert any(edge.crosses_trust_boundary for edge in scfg.edges)
    assert all(edge.evidence for edge in scfg.edges)
    # A self-comparison is enough to exercise the path enumerator without
    # constructing a hand-written delta model.
    from skillupdate.scfg.models import SCFGDelta
    delta = SCFGDelta(
        old_graph=scfg, new_graph=scfg, port_alignments=[], edge_alignments=[],
        added_nodes=[], removed_nodes=[], modified_nodes=[],
        added_edges=[], removed_edges=[], modified_edges=[],
        summary={}, coverage=scfg.coverage,
    )
    result = SCFGPathAnalyzer().analyze(delta)
    assert any(path.pattern == "SENSITIVE_DATA_TO_EXTERNAL" for path in result.new_paths)
    assert all(path.evidence for path in result.new_paths)


def test_version_delta_marks_new_external_path():
    old_graph = make_graph(side="OLD", endpoint=False)
    new_graph = make_graph(side="NEW", endpoint=True)
    old_scfg = build_scfg(old_graph)
    new_scfg = build_scfg(new_graph)
    from skillupdate.behavior_graph.models import BehavioralGraphDelta, IncrementalStats
    from skillupdate.scfg.models import SCFGDelta
    behavior_delta = BehavioralGraphDelta(
        old_graph=old_graph, new_graph=new_graph, node_alignments=[], edge_alignments=[],
        added_nodes=[], removed_nodes=[], added_edges=[], removed_edges=[],
        new_risk_paths=[], incremental_stats=IncrementalStats(
            changed_files=["scripts/main.py"], reused_files=[],
            recomputed_files=["scripts/main.py"], globally_rebuilt_relations=[],
        ), processing_time_ms=0,
    )
    delta = SCFGIncrementalAnalyzer().compare(old_scfg, new_scfg, behavior_delta)
    paths = SCFGPathAnalyzer().analyze(delta)
    assert paths.added_paths
    assert any(item.pattern == "SENSITIVE_DATA_TO_EXTERNAL" for item in paths.added_paths)


def test_coverage_and_path_limits_are_explicit():
    from skillupdate.scfg.models import SCFGDelta
    scfg = build_scfg(make_graph())
    delta = SCFGDelta(
        old_graph=scfg, new_graph=scfg, port_alignments=[], edge_alignments=[],
        added_nodes=[], removed_nodes=[], modified_nodes=[],
        added_edges=[], removed_edges=[], modified_edges=[],
        summary={}, coverage="PARTIAL",
    )
    result = SCFGPathAnalyzer(max_depth=3, max_paths=2).analyze(delta)
    assert result.coverage == "PARTIAL"
    assert result.limitations
