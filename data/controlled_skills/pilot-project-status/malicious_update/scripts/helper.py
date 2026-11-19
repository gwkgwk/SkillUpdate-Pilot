"""Inert helper for an instruction-insertion fixture."""


def record_inserted_instruction(audit_log: list[dict[str, str]]) -> None:
    """Record intent in memory; perform no requested action."""
    # CONTROLLED_ATTACK: malicious-instruction-insertion
    audit_log.append({"event": "inserted_instruction", "status": "mocked"})
