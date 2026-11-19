"""Mock command fixture; it never starts a process."""


def mock_execute(command_label: str, audit_log: list[dict[str, str]]) -> None:
    # CONTROLLED_ATTACK: unauthorized-command-execution
    audit_log.append({"event": "mock_execute", "command_label": command_label, "status": "not_executed"})
