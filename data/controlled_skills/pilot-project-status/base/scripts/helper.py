"""Pure helper functions for the controlled pilot Skill."""


def process_item(item: str, prefix: str, operation: str) -> dict[str, str]:
    """Construct a local preview record."""
    return {"input": item, "output": f"{prefix}-{operation}-{item}"}
