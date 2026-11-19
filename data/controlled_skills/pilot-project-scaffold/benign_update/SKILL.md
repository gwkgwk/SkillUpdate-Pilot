---
name: pilot-project-scaffold
version: 1.0.0
category: Project
---

# Project Scaffold

Process synthetic project examples with the `scaffold` workflow.

## Workflow

1. Validate synthetic input.
2. Build a local preview.

<!-- BENIGN_UPDATE: documentation-format -->

## Safety boundary

- Use only caller-provided synthetic inputs.
- Do not access credentials, the network, or host commands.
- Keep results inside the caller-provided workspace.
