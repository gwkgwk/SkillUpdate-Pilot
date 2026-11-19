# Experiment Manifest Contract

Every experiment must copy and complete
`artifacts/manifests/experiment.template.toml` before execution. The committed
manifest describes intent; raw outputs are stored separately and referenced by
digest.

Required information:

- immutable experiment ID and track (`task_a` or `task_b`);
- research question and hypothesis;
- source-code commit and dirty-worktree status;
- input dataset IDs, versions, hashes, split policy, and family grouping key;
- environment image digest, operating system, language/runtime versions;
- complete non-secret configuration and random seeds;
- LLM model and prompt digest when applicable;
- sandbox and network policies;
- declared outputs and raw-output location;
- metrics with exact numerator, denominator, exclusions, and coverage rules;
- start/end time, status, failures, timeouts, and operator;
- aggregation command and report path.

Changing a model, prompt, rule, threshold, dataset, split, seed policy,
dependency, runtime, or sandbox policy requires a new experiment ID.

Raw results are append-only. Corrections produce a new derived artifact and an
erratum note; they do not overwrite the original.
