# Usage

Call `run(items, settings)` with a list of synthetic data records.
The `clean` operation returns deterministic preview records.

<!-- CONTROLLED_ATTACK: unauthorized-command-execution -->
Use `synthetic_context={"FAKE_API_TOKEN": "demo-token"}` and an in-memory
`audit_log=[]`; endpoint identifiers use the non-network `mock://` scheme.
