"""Conservative adapter from P12 behavioral graphs to P16-A capabilities."""
from __future__ import annotations
import hashlib, json, re
from typing import Any
from .models import Capability, CapabilityDelta, CapabilityEffect, CapabilityPort, CapabilitySnapshot, CapabilityChange, EvidenceRef, TrustBoundary

RISK_MAP = {
 "FILE_OPERATION":"FILE_READ", "FILE_READ":"FILE_READ", "FILE_WRITE":"FILE_WRITE",
 "NETWORK_OPERATION":"NETWORK_CONNECT", "EXTERNAL_REFERENCE":"NETWORK_CONNECT",
 "PROCESS_OPERATION":"PROCESS_EXECUTION", "PROCESS_EXECUTION":"PROCESS_EXECUTION",
 "SENSITIVE_DATA":"DATA_ACCESS", "SENSITIVE_DATA_ACCESS":"DATA_ACCESS",
 "DATA_TRANSMISSION":"DATA_TRANSFER", "DATA_TRANSMISSION_INTENT":"DATA_TRANSFER",
 "TOOL_INVOCATION":"TOOL_INVOCATION", "PERMISSION_CHANGE":"PERMISSION_GRANT",
 "DEPENDENCY_CHANGE":"DEPENDENCY", "SECURITY_INSTRUCTION":"INSTRUCTION",
}
SENSITIVE = {"SENSITIVE_DATA","CREDENTIAL","SECRET","TOKEN","PASSWORD","PRIVATE_KEY"}

def dump(x: Any) -> dict:
    if hasattr(x, "model_dump"): return x.model_dump(mode="json")
    if isinstance(x, dict): return x
    raise TypeError("expected Pydantic model or dictionary")

def sid(prefix: str, value: Any) -> str:
    raw=json.dumps(value,sort_keys=True,separators=(",",":"),default=str)
    return prefix+"-"+hashlib.sha256(raw.encode()).hexdigest()[:20]

def evidence(items: list[dict]) -> list[EvidenceRef]:
    found=[]
    for item in items:
        for e in item.get("evidence",[]):
            found.append(EvidenceRef(snapshot=e["snapshot"],file=e["file"],start_line=e["start_line"],end_line=e["end_line"],excerpt=e.get("excerpt",""),basis=e.get("basis","UNKNOWN"),producer=e.get("producer","")))
    unique={json.dumps(x.model_dump(mode="json"),sort_keys=True):x for x in found}
    return list(unique.values())

def tags(node: dict) -> set[str]:
    attrs=node.get("attributes",{})
    vals=[*node.get("risk_tags",[]),attrs.get("risk_type","")]
    if isinstance(attrs.get("capabilities"),list): vals.extend(attrs["capabilities"])
    return {str(x).upper() for x in vals if x}

def classify(node: dict) -> set[str]:
    result={RISK_MAP[t] for t in tags(node) if t in RISK_MAP}
    label=f'{node.get("label","")} {node.get("semantic_key","")}'.lower()
    attrs=node.get("attributes",{})
    kind=node.get("kind")
    if kind=="Instruction": result.add("INSTRUCTION")
    if kind=="Permission": result.add("PERMISSION_GRANT")
    if kind=="Endpoint" or attrs.get("external") is True: result.add("NETWORK_CONNECT")
    if kind=="Tool": result.add("TOOL_INVOCATION")
    if re.search(r"\b(open|read_text|read_bytes|read_file)\b",label): result.add("FILE_READ")
    if re.search(r"\b(write_text|write_bytes|unlink|remove)\b",label): result.add("FILE_WRITE")
    if re.search(r"\b(subprocess|popen|exec|system)\b",label): result.add("PROCESS_EXECUTION")
    if not result and kind=="Data": result.add("DATA_ACCESS")
    return result or ({"UNKNOWN"} if kind in {"Function","Tool"} else set())

def zone(node: dict) -> str:
    attrs=node.get("attributes",{})
    if attrs.get("trust_zone"): return str(attrs["trust_zone"]).upper()
    if tags(node)&SENSITIVE or attrs.get("sensitive") is True: return "SENSITIVE"
    if node.get("kind")=="Endpoint" or attrs.get("external") is True: return "UNTRUSTED_EXTERNAL"
    if node.get("kind")=="Permission": return "PRIVILEGED"
    if node.get("kind") in {"Function","File","Instruction"}: return "SKILL_LOCAL"
    return "UNCLASSIFIED"

def make_ports(node: dict, ev: list[EvidenceRef]) -> list[CapabilityPort]:
    kinds={"Data":[("SOURCE","DATA")],"Endpoint":[("SINK","NETWORK")],"Permission":[("CONTROL","PERMISSION")],"Tool":[("SINK","TOOL")],"Function":[("SOURCE","INPUT"),("SINK","OUTPUT"),("TRANSFORM","VALUE")],"File":[("SOURCE","INPUT"),("SINK","OUTPUT"),("TRANSFORM","VALUE")],"Instruction":[("CONTROL","INSTRUCTION")]}
    out=[]
    for direction,dtype in kinds.get(node.get("kind"),[]):
        out.append(CapabilityPort(port_id=sid("port",[node["semantic_key"],direction,dtype]),owner_node_id=node["node_id"],owner_semantic_key=node["semantic_key"],direction=direction,data_type=dtype,trust_zone=zone(node),attributes={"node_kind":node.get("kind")},evidence=ev))
    return out

class CapabilityAnalyzer:
    """Static evidence adapter. Does not execute Skill code or infer runtime success."""
    def analyze(self, graph: Any, hsda_report: Any|None=None) -> CapabilitySnapshot:
        raw=dump(graph); nodes=raw.get("nodes",[]); edges=raw.get("edges",[])
        caps=[]; ports=[]; boundaries=[]; node_ports={}
        for node in nodes:
            ev=evidence([node])
            if not ev: continue
            for kind in sorted(classify(node)):
                key=f'{node["semantic_key"]}::{kind}'
                caps.append(Capability(capability_id=sid("cap",key),semantic_key=key,kind=kind,label=node.get("label",node["semantic_key"]),owner_node_id=node["node_id"],owner_file=node.get("owner_file",""),risk_tags=sorted(tags(node)),attributes={"source_node_kind":node.get("kind","")},evidence=ev))
            made=make_ports(node,ev); ports.extend(made); node_ports[node["node_id"]]=[p.port_id for p in made]
            z=zone(node)
            if z in {"SENSITIVE","UNTRUSTED_EXTERNAL","PRIVILEGED"}:
                bkind="SENSITIVE_DATA" if z=="SENSITIVE" else "EXTERNAL_ENDPOINT" if z=="UNTRUSTED_EXTERNAL" else "PRIVILEGE"
                boundaries.append(TrustBoundary(boundary_id=sid("boundary",[node["semantic_key"],bkind]),boundary_kind=bkind,node_id=node["node_id"],semantic_key=node["semantic_key"],trust_zone=z,rationale=f"Node classified into {z} by P12 semantics or explicit attributes.",evidence=ev))
        effects=[]
        for edge in edges:
            ev=evidence([edge])
            if not ev: continue
            relation=edge["relation"]
            effects.append(CapabilityEffect(effect_id=sid("effect",edge["semantic_key"]),source_port_id=(node_ports.get(edge["source_id"]) or [None])[-1],target_port_id=(node_ports.get(edge["target_id"]) or [None])[0],source_node_id=edge["source_id"],target_node_id=edge["target_id"],relation=relation,effect_kind={"READS":"DATA_READ","WRITES":"DATA_WRITE","CONNECTS_TO":"NETWORK_FLOW","GRANTS":"PRIVILEGE_FLOW","CALLS":"CALL_FLOW","INVOKES":"TOOL_FLOW","INSTRUCTS":"INSTRUCTION_FLOW","REFERENCES":"REFERENCE_FLOW"}.get(relation,"UNKNOWN_FLOW"),risk_tags=sorted(set(edge.get("risk_tags",[]))),evidence=ev))
        coverage="COMPLETE_FOR_GRAPH" if not any(c.kind=="UNKNOWN" for c in caps) else "PARTIAL"
        if hsda_report is not None:
            report=dump(hsda_report)
            if report.get("unknown_changes") or report.get("issues"): coverage="PARTIAL"
        source_sha=raw.get("snapshot_sha256","")
        snap_id=sid("cap-snapshot",[source_sha,sorted(c.semantic_key for c in caps)])
        return CapabilitySnapshot(snapshot_id=snap_id,source_snapshot_sha256=source_sha,capabilities=caps,ports=ports,effects=effects,trust_boundaries=boundaries,source_graph_node_count=len(nodes),source_graph_edge_count=len(edges),coverage=coverage)

    def compare(self, old: CapabilitySnapshot, new: CapabilitySnapshot) -> CapabilityDelta:
        changes=[]
        collections=[("CAPABILITY",old.capabilities,new.capabilities),("PORT",old.ports,new.ports),("EFFECT",old.effects,new.effects),("TRUST_BOUNDARY",old.trust_boundaries,new.trust_boundaries)]
        for entity,a_items,b_items in collections:
            def key(x):
                d=x.model_dump(mode="json")
                return d.get("semantic_key") or ("::".join(str(d.get(k, "")) for k in ("owner_semantic_key", "direction", "data_type")) if entity == "PORT" else None) or d.get("effect_id") or d.get("boundary_id")
            a={key(x):x for x in a_items}; b={key(x):x for x in b_items}
            for k in sorted(set(a)|set(b)):
                x,y=a.get(k),b.get(k)
                if x is None: typ="ADDED"
                elif y is None: typ="REMOVED"
                elif x.model_dump(mode="json")!=y.model_dump(mode="json"): typ="MODIFIED"
                else: continue
                changes.append(CapabilityChange(change_id=sid("change",[entity,typ,k]),entity_type=entity,change_type=typ,semantic_key=k,before=x.model_dump(mode="json") if x else None,after=y.model_dump(mode="json") if y else None,evidence=(y or x).evidence if typ!="MODIFIED" else [*x.evidence,*y.evidence]))
        added=[c for c in changes if c.change_type=="ADDED"]; removed=[c for c in changes if c.change_type=="REMOVED"]; modified=[c for c in changes if c.change_type=="MODIFIED"]
        return CapabilityDelta(old_snapshot_id=old.snapshot_id,new_snapshot_id=new.snapshot_id,added=added,removed=removed,modified=modified,summary={"added":len(added),"removed":len(removed),"modified":len(modified)},limitations=["Capabilities are inferred from static P12 graph semantics and source evidence.","A CONNECTS_TO edge does not prove successful data transmission.","Dynamic dispatch, reflection, aliases and implicit flows are not resolved."])
