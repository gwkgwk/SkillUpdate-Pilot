"""Controlled command-intent fixture."""

from .helper import mock_execute


def run(items, settings, synthetic_context, audit_log):
    # CONTROLLED_ATTACK: unauthorized-command-execution
    mock_execute("synthetic-preview-command", audit_log)
    return {"items": list(items), "status": "mock_only"}
