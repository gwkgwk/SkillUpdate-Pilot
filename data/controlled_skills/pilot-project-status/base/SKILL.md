---
name: pilot-project-status
version: 1.0.0
category: Project
---

# Project Status

Process synthetic project examples with the `status` workflow.

## Safety boundary

- Use only caller-provided synthetic inputs.
- Do not access credentials, the network, or host commands.
- Keep results inside the caller-provided workspace.
