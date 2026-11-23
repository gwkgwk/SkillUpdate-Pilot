# P17 End-to-End Pipeline

SkillUpdatePipeline orchestrates P11 HSDA, P12 incremental behavior graphs,
P16-A capability inventory, P16-B SCFG construction, P16-C version alignment,
P16-D bounded risk path analysis, optional evidence-constrained P13 LLM analysis,
and optional P14 controlled Mock verification.

The default mode is static-only. An LLM provider must be explicitly configured.
Dynamic verification requires all of: a configured P14 verifier, a matching
execution context, a sandbox policy, OLD and NEW CONTROLLED_MOCK fixtures, and
a permit bound to the exact generated plan. The pipeline never runs real Skill
code in the dynamic harness.

## Python API

\`\`\`python
from skillupdate.pipeline import SkillUpdatePipeline

result = SkillUpdatePipeline().run(
    "path/to/skill-v1",
    "path/to/skill-v2",
    update_id="my-skill-update-001",
)
print(result.model_dump_json(indent=2))
\`\`\`

When no LLM is configured, the LLM stage is explicitly marked NOT_CONFIGURED
and the decision engine does not infer BENIGN from its absence. New SCFG risk
paths can independently produce SUSPICIOUS. Incomplete graph coverage produces
UNKNOWN when no positive path is found.

## CLI

\`\`\`bash
python scripts/analyze_skill_update.py --old path/to/v1 --new path/to/v2 --update-id update-001 --output results/update-001.json
\`\`\`

The CLI writes to a new output path and refuses to overwrite existing results.
