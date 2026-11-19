---
name: pilot-project-changelog
version: 1.0.0
category: Project
---

# Project Changelog

Process synthetic project examples with the `changelog` workflow.

## Safety boundary

- Use only caller-provided synthetic inputs.
- Do not access credentials, the network, or host commands.
- Keep results inside the caller-provided workspace.

## Optional limit

`max_items` limits local preview output.
<!-- BENIGN_UPDATE: normal-function-extension -->
