# LLM Security Analyzer

P13 implements an evidence-constrained advisory analyzer. `package.py` converts
HSDA and incremental graph outputs into a catalog-addressed `AnalysisPackage`;
`prompts.py` keeps fixed system instructions separate from the untrusted Skill
data envelope; `analyzer.py` validates JSON and every evidence/path reference,
enforces budgets, retries and rate limits, and stores request/raw/parsed audit
records. `provider.py` defines the replaceable provider boundary and an optional
OpenAI-compatible HTTP adapter that reads its key only from an environment
variable.

An analyzer result is advisory. Invalid JSON, schema violations, fabricated
locations, provider failures, and budget exhaustion return `UNKNOWN`. No code in
this package executes a Skill or gives model output tool authority.
