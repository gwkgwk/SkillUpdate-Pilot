from skillupdate.behavior_graph.models import BehaviorEdge, BehaviorGraph, BehaviorNode, GraphEvidence
from skillupdate.capability import CapabilityAnalyzer

def ev(line=1):
    return GraphEvidence(snapshot="NEW",file="scripts/main.py",start_line=line,end_line=line,excerpt="static evidence",basis="STATIC_FACT",producer="test")

def make_graph(endpoint=True):
    nodes=[
      BehaviorNode(node_id="data",kind="Data",semantic_key="credential:token",label="credential token",owner_file="scripts/main.py",basis="STATIC_FACT",evidence=[ev()],risk_tags=["SENSITIVE_DATA"],attributes={"sensitive":True}),
      BehaviorNode(node_id="fn",kind="Function",semantic_key="function:send",label="send",owner_file="scripts/main.py",basis="STATIC_FACT",evidence=[ev(2)]),
    ]
    edges=[BehaviorEdge(edge_id="read",source_id="fn",target_id="data",relation="READS",semantic_key="reads-token",owner_files=["scripts/main.py"],basis="RULE_INFERENCE",evidence=[ev(3)])]
    if endpoint:
      nodes.append(BehaviorNode(node_id="api",kind="Endpoint",semantic_key="endpoint:api",label="api endpoint",owner_file="scripts/main.py",basis="STATIC_FACT",evidence=[ev(8)],risk_tags=["EXTERNAL_REFERENCE"],attributes={"external":True}))
      edges.append(BehaviorEdge(edge_id="connect",source_id="fn",target_id="api",relation="CONNECTS_TO",semantic_key="connects-api",owner_files=["scripts/main.py"],basis="RULE_INFERENCE",evidence=[ev(9)]))
    return BehaviorGraph(snapshot_id="s",snapshot_sha256="a"*64,nodes=nodes,edges=edges)

def test_extracts_typed_capabilities_ports_effects_and_boundaries():
    result=CapabilityAnalyzer().analyze(make_graph())
    assert {x.kind for x in result.capabilities}>={"DATA_ACCESS","NETWORK_CONNECT"}
    assert {x.boundary_kind for x in result.trust_boundaries}>={"SENSITIVE_DATA","EXTERNAL_ENDPOINT"}
    assert result.ports and result.effects

def test_delta_detects_removed_endpoint_capability_and_edge():
    analyzer=CapabilityAnalyzer()
    old=analyzer.analyze(make_graph(True)); new=analyzer.analyze(make_graph(False))
    delta=analyzer.compare(old,new)
    assert delta.summary["removed"]>0
    assert any(x.entity_type=="CAPABILITY" for x in delta.removed)
    assert any(x.entity_type=="EFFECT" for x in delta.removed)

def test_digest_is_deterministic():
    analyzer=CapabilityAnalyzer()
    assert analyzer.analyze(make_graph()).digest()==analyzer.analyze(make_graph()).digest()
