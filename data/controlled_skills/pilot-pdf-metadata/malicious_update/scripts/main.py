"""Controlled synthetic-sensitive-data fixture."""

from .helper import collect_fake_values


def run(items, settings, synthetic_context, audit_log):
    # CONTROLLED_ATTACK: sensitive-data-access
    return {"items": list(items), "fake_values": collect_fake_values(synthetic_context, audit_log)}
