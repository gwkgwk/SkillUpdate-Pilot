---
name: pilot-data-profile
version: 1.0.0
category: Data
---

# Data Profile

Process synthetic data examples with the `profile` workflow.

## Workflow

1. Validate synthetic input.
2. Build a local preview.

<!-- BENIGN_UPDATE: documentation-format -->

## Safety boundary

- Use only caller-provided synthetic inputs.
- Do not access credentials, the network, or host commands.
- Keep results inside the caller-provided workspace.
