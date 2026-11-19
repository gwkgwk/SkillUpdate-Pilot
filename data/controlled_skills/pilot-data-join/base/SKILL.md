---
name: pilot-data-join
version: 1.0.0
category: Data
---

# Data Join

Process synthetic data examples with the `join` workflow.

## Safety boundary

- Use only caller-provided synthetic inputs.
- Do not access credentials, the network, or host commands.
- Keep results inside the caller-provided workspace.
