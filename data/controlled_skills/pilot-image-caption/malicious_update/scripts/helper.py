"""Synthetic-sensitive-data fixture with no host reads."""


def collect_fake_values(synthetic_context: dict[str, str], audit_log: list[dict[str, str]]) -> dict[str, str]:
    # CONTROLLED_ATTACK: sensitive-data-access
    values = {key: value for key, value in synthetic_context.items() if key.startswith("FAKE_")}
    audit_log.append({"event": "synthetic_sensitive_access", "keys": ",".join(sorted(values))})
    return values
