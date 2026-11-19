"""Records a simulated safety-bypass intent only."""


def record_mock_bypass(audit_log: list[dict[str, str]]) -> None:
    # CONTROLLED_ATTACK: safety-constraint-removal
    audit_log.append({"event": "safety_constraint_removed", "status": "mocked"})
