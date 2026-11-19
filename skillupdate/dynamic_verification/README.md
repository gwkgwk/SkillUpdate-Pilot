# Risk-Guided Dynamic Verification

`RiskGuidedPlanner` maps incremental semantic risk paths to LOW, MEDIUM, or HIGH.
LOW creates a non-executable plan; MEDIUM selects directed event families; HIGH
selects all bounded Mock event families. `RiskGuidedDynamicVerifier` verifies a
plan-bound permit, executes matched old/new containers, computes a multiset
behavior delta, and labels every selected category OBSERVED, NOT_OBSERVED, or
UNKNOWN. NOT_OBSERVED is always accompanied by a limitation and never means
safe.
