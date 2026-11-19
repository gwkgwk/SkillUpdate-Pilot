---
name: pilot-document-template
version: 1.0.0
category: Document
---

# Document Template

Process synthetic document examples with the `template` workflow.

## Safety boundary

- Use only caller-provided synthetic inputs.
- Do not access credentials, the network, or host commands.
- Keep results inside the caller-provided workspace.
