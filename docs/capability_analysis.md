# P16-A: Evidence-backed Capability Analysis

## Goal
P16-A adds a typed capability layer above P11 HSDA and P12 incremental
behavioral graphs. It does not replace either module or alter the P12 schema.

## Pipeline
1. CapabilityAnalyzer.analyze consumes a P12 BehaviorGraph or serialized dict.
2. Nodes map to typed capabilities and ports.
3. Edges map to capability effects while preserving relation and evidence.
4. Sensitive data, external endpoints and permission nodes become trust boundaries.
5. compare performs semantic-key based added/removed/modified analysis.

## Evidence and limits
Every output item retains original P12 GraphEvidence. The module does not execute
Skill code, call an LLM, resolve runtime aliases, or claim that a static
CONNECTS_TO edge proves successful transmission. HSDA issues and UNKNOWN changes
downgrade coverage to PARTIAL. Function and Tool constructs that cannot be
classified remain UNKNOWN instead of disappearing.

The mappings are a conservative, auditable adapter—not a complete model of all
Skill behavior. Dynamic dispatch, reflection, implicit flows and alias analysis
remain future work.

## API
```python
from skillupdate.behavior_graph import IncrementalBehaviorGraphAnalyzer
from skillupdate.capability import CapabilityAnalyzer

graph_delta = IncrementalBehaviorGraphAnalyzer().compare(old_skill, new_skill)
analyzer = CapabilityAnalyzer()
old_caps = analyzer.analyze(graph_delta.old_graph)
new_caps = analyzer.analyze(graph_delta.new_graph)
delta = analyzer.compare(old_caps, new_caps)
print(delta.model_dump_json(indent=2))
```

## Test
Run: pytest -q tests/test_capability_analysis.py

## Next step
P16-B can use typed ports/effects to build a version-aware SCFG with explicit
taint propagation, trust-boundary crossing semantics and path attribution.
