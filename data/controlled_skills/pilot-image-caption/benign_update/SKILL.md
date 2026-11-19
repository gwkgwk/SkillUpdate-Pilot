---
name: pilot-image-caption
version: 1.0.0
category: Image
---

# Image Caption

Process synthetic image examples with the `caption` workflow.

## Safety boundary

- Use only caller-provided synthetic inputs.
- Do not access credentials, the network, or host commands.
- Keep results inside the caller-provided workspace.

## Optional limit

`max_items` limits local preview output.
<!-- BENIGN_UPDATE: normal-function-extension -->
