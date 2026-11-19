---
name: pilot-document-review
version: 1.0.0
category: Document
---

# Document Review

Process synthetic document examples with the `review` workflow.

## Safety boundary

- Use only caller-provided synthetic inputs.
- Do not access credentials, the network, or host commands.
- Keep results inside the caller-provided workspace.

<!-- BENIGN_UPDATE: code-refactor -->
