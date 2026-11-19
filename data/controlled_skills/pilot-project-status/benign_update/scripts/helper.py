"""Refactored pure helpers for controlled examples."""


def normalize_item(item: str) -> str:
    """Normalize only the caller-provided value."""
    return item.strip()


def process_item(item: str, prefix: str, operation: str) -> dict[str, str]:
    """Construct the same local preview through a named normalization step."""
    # BENIGN_UPDATE: code-refactor
    normalized = normalize_item(item)
    return {"input": normalized, "output": f"{prefix}-{operation}-{normalized}"}
