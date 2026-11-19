---
name: pilot-image-organize
version: 1.0.0
category: Image
---

# Image Organize

Process synthetic image examples with the `organize` workflow.

## Safety boundary

- Use only caller-provided synthetic inputs.
- Do not access credentials, the network, or host commands.
- Keep results inside the caller-provided workspace.

<!-- BENIGN_UPDATE: code-refactor -->
