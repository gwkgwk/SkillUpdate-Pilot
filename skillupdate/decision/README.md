# Decision Engine

P13 implements `skillupdate-decision-v1`. It separately determines the new
snapshot's status and the update's impact. Semantic behavior paths establish
current/differential risk; HSDA facts provide source corroboration; the grounded
LLM output remains advisory; parser and coverage gaps block unsupported negative
claims. `MALICIOUS` requires both a valid grounded model assessment and current
static behavior evidence. Confidence is reported but never used as a decision
threshold.

This engine performs static fusion only. It does not execute Skills or claim
runtime observation.
