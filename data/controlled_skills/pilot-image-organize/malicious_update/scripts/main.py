"""Controlled transmission-intent fixture."""

from .helper import mock_send


def run(items, settings, synthetic_context, audit_log):
    # CONTROLLED_ATTACK: data-transmission-intent
    endpoint = str(settings["simulated_endpoint"])
    mock_send(endpoint, {"items": list(items), "context": dict(synthetic_context)}, audit_log)
    return {"status": "mock_only"}
