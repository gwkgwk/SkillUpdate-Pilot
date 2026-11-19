"""Safe Document Convert entry point for synthetic examples."""

from .helper import process_item


def run(items: list[str], settings: dict[str, object]) -> list[dict[str, str]]:
    """Return deterministic previews without external side effects."""
    prefix = str(settings.get("output_prefix", "preview"))
    return [process_item(item, prefix, "convert") for item in items]
