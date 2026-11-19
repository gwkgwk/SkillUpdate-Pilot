# Stage Acceptance Template

Use this template at the end of every project stage.

## Scope and decision

- Stage ID:
- Track: Task A / Task B / governance
- Objective:
- Acceptance status: accepted / rejected / partial / blocked
- Evidence reviewed:

## Required handoff

1. **Files modified:** exact paths and purpose.
2. **Functionality implemented:** observable behavior only.
3. **Commands executed:** exact reproducible commands, with secrets omitted.
4. **Test status:** passed, failed, skipped, and not run counts with reasons.
5. **Actual outputs:** paths, hashes, metrics, and representative results.
6. **Remaining issues:** failures, missing artifacts, assumptions, and risks.
7. **Next-stage inputs:** concrete artifacts or decisions required.

## Reproducibility checks

- [ ] Worktree state recorded.
- [ ] Source and data provenance recorded.
- [ ] Configuration and environment versions recorded.
- [ ] Raw results preserved and hashed.
- [ ] Task A and Task B outputs remain separate.
- [ ] No secret or sensitive host data was accessed.
- [ ] Dynamic work, if any, stayed inside the approved isolation boundary.
- [ ] Sample-family split leakage check passed.
