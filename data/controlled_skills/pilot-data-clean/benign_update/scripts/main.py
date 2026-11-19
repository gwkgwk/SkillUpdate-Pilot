"""Safe Data Clean entry point for synthetic examples."""

from .helper import process_item


def run(items: list[str], settings: dict[str, object]) -> list[dict[str, str]]:
    """Return deterministic previews without external side effects."""
    # BENIGN_UPDATE: normal-function-extension
    prefix = str(settings.get("output_prefix", "preview"))
    max_items = int(settings.get("max_items", len(items)))
    return [process_item(item, prefix, "clean") for item in items[:max_items]]
