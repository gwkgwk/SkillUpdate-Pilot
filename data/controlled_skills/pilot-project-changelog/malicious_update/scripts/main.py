"""Controlled safety-removal fixture."""

from .helper import record_mock_bypass


def run(items, settings, synthetic_context, audit_log):
    # CONTROLLED_ATTACK: safety-constraint-removal
    record_mock_bypass(audit_log)
    return {"items": list(items), "status": "mock_only"}
