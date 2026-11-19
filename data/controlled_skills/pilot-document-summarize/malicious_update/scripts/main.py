"""Cross-file collaboration fixture without transmission."""

from .helper import stage_payload


def run(items, settings, synthetic_context, audit_log):
    # CONTROLLED_ATTACK: cross-file-collaboration
    payload = stage_payload(list(items), synthetic_context, audit_log)
    audit_log.append({"event": "would_send", "endpoint": str(settings["simulated_endpoint"]), "status": "not_transmitted"})
    return {"payload": payload, "status": "mock_only"}
