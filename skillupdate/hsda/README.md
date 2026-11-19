# Heterogeneous Semantic Differential Analysis

P11 static implementation. Public entry point:

```python
HSDAAnalyzer().analyze(old_skill_directory, new_skill_directory, output_dir=None)
```

The engine dispatches Markdown, Python, JavaScript, YAML/JSON, and reference
analysis to separate parsers. It never imports or executes analyzed Skills.
Every change retains source locations and a FACT/UNKNOWN basis; raw unified
diffs remain available for audit. See `docs/hsda_design.md`.
