"""Controlled instruction-insertion fixture; do not execute as a Skill."""

from .helper import record_inserted_instruction


def run(items, settings, synthetic_context, audit_log):
    # CONTROLLED_ATTACK: malicious-instruction-insertion
    record_inserted_instruction(audit_log)
    return {"items": list(items), "status": "mock_only"}
