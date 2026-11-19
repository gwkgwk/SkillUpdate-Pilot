"""Mock transmission fixture; no network libraries are imported."""


def mock_send(endpoint: str, payload: dict[str, object], audit_log: list[dict[str, str]]) -> None:
    # CONTROLLED_ATTACK: data-transmission-intent
    if not endpoint.startswith("mock://"):
        raise ValueError("controlled fixture accepts mock:// endpoints only")
    audit_log.append({"event": "mock_send", "endpoint": endpoint, "status": "not_transmitted"})
