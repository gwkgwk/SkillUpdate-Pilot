# P16 SCFG and P17 end-to-end implementation

## Implemented stages

- P16-A: typed capability inventory, ports, effects, trust boundaries and evidence.
- P16-B: port-level Security Capability Flow Graph (SCFG).
- P16-C: cross-version port/edge alignment and added/removed/modified deltas.
- P16-D: bounded candidate path enumeration and evidence attribution.
- P17: static-first pipeline joining HSDA, behavior graphs, capabilities, SCFG,
  optional evidence-constrained LLM analysis, optional controlled Mock verification,
  and conservative final decision fusion.

## Flow semantics

READS is oriented from the data object to the function input. WRITES is oriented
from the function output to the destination. CONNECTS_TO is oriented from the
function output to the endpoint. CALLS, INVOKES, GRANTS, INSTRUCTS and REFERENCES
remain typed control or reference flows. A function-level may-flow edge is
emitted only when the function has both a read and an output operation; it is
marked POSSIBLE because argument and return-value propagation are not resolved.

## Decision semantics

A new SCFG candidate path can produce SUSPICIOUS. A path alone cannot produce
MALICIOUS. MALICIOUS is retained only when the existing evidence-grounded
Decision Engine reaches that conclusion. Incomplete graph coverage prevents
negative/benign conclusions. LLM analysis is optional and omitted analysis
remains UNKNOWN. Dynamic verification is opt-in and accepts only the existing
P14 CONTROLLED_MOCK fixture contract.

## Run

\`\`\`bash
pip install -r requirements.txt
python -m pytest -q tests/scfg tests/pipeline tests/test_capability_analysis.py
python scripts/analyze_skill_update.py --old ./skill-v1 --new ./skill-v2 --update-id demo-001 --output ./results/demo-001.json
\`\`\`

The pipeline does not execute Skill source. Dynamic P14 verification must be
configured separately with a reviewed image, approved fixture root, exact
CONTROLLED_MOCK fixtures, and a permit bound to the generated plan.
