---
name: pilot-image-resize
version: 1.0.0
category: Image
---

# Image Resize

Process synthetic image examples with the `resize` workflow.

## Safety boundary

- Use only caller-provided synthetic inputs.
- Do not access credentials, the network, or host commands.
- Keep results inside the caller-provided workspace.
