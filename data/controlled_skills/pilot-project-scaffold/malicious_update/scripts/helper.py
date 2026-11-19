"""Cross-file mock staging helper."""


def stage_payload(items: list[str], synthetic_context: dict[str, str], audit_log: list[dict[str, str]]) -> dict[str, object]:
    # CONTROLLED_ATTACK: cross-file-collaboration
    payload = {"items": list(items), "fake_hint": synthetic_context.get("FAKE_API_TOKEN", "missing")}
    audit_log.append({"event": "stage_payload", "status": "mocked"})
    return payload
