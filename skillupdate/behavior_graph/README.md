# Incremental Behavioral Graph Analysis

P12 static implementation. Public entry point:

```python
IncrementalBehaviorGraphAnalyzer().compare(old_skill, new_skill)
```

The analyzer builds old/new evidence graphs, reuses unchanged per-file
fragments, aligns renamed/refactored nodes and relations, and identifies only
semantically supported new risk paths. It never executes a Skill. See
`docs/behavior_graph_design.md`.
