# P16-B/C/D: Security Capability Flow Graph

P16 consumes the evidence-backed P16-A capability inventory and P12 behavior
graph. It creates a port-level graph, aligns graph components across versions,
and searches bounded candidate security paths.

## Direction semantics

- READS: data source port -> reading function input port.
- WRITES: writing function output port -> destination data sink.
- CONNECTS_TO: function output port -> endpoint network sink.
- CALLS, INVOKES, GRANTS, INSTRUCTS, REFERENCES: typed control, tool, privilege,
  instruction, and reference flows.
- FUNCTION_SCOPE_MAY_FLOW: a possible in-function input-to-output edge when a
  function both reads data and has a write/network output. This is an
  over-approximation and is always marked POSSIBLE.

Every node and edge retains source evidence. Unknown mappings remain unresolved
and lower coverage; they are not silently discarded.

## Version analysis

SCFGIncrementalAnalyzer uses P12 node alignments to align capability ports,
then aligns flow edges by mapped endpoints and relation. New, removed and
modified components are reported independently. A risk path is marked new if
its semantic path is new or if one of its components was added/modified.

## Path analysis

The bounded analyzer searches sensitive source ports to external/network sinks,
plus direct process, instruction and privilege paths. Search depth and result
count are capped. Paths are static rule inferences, not proof of execution.

## API

\`\`\`python
from skillupdate.capability import CapabilityAnalyzer
from skillupdate.scfg import SCFGBuilder, SCFGIncrementalAnalyzer, SCFGPathAnalyzer

old_caps = CapabilityAnalyzer().analyze(old_behavior_graph)
new_caps = CapabilityAnalyzer().analyze(new_behavior_graph)
builder = SCFGBuilder()
old_scfg = builder.build(old_behavior_graph, old_caps)
new_scfg = builder.build(new_behavior_graph, new_caps)
delta = SCFGIncrementalAnalyzer().compare(old_scfg, new_scfg, behavior_delta)
paths = SCFGPathAnalyzer().analyze(delta)
\`\`\`
