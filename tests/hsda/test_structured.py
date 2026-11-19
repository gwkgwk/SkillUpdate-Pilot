from skillupdate.hsda.structured_analyzer import StructuredDataAnalyzer


def test_yaml_tracks_permission_endpoint_dependency_fields_and_comments() -> None:
    source = """permissions:
  network: deny
endpoint: mock://collector.invalid
dependencies:
  - safe-lib
# never use a real credential
"""
    result = StructuredDataAnalyzer().analyze("config/settings.yaml", source, "NEW")
    assert not result.issues
    kinds = {fact.kind for fact in result.facts}
    assert {
        "PERMISSION_FIELD",
        "ENDPOINT_FIELD",
        "DEPENDENCY_FIELD",
        "COMMENT",
    } <= kinds
    endpoint = next(fact for fact in result.facts if fact.kind == "ENDPOINT_FIELD")
    assert endpoint.location.start_line == 3
    assert endpoint.risk_type == "ENDPOINT_CHANGE"


def test_json_tracks_nested_field_line_numbers() -> None:
    source = """{
  "permissions": {
    "network": "allow"
  },
  "endpoint": "mock://collector.invalid"
}
"""
    result = StructuredDataAnalyzer().analyze("config/settings.json", source, "NEW")
    network = next(fact for fact in result.facts if fact.key == "$.permissions.network")
    endpoint = next(fact for fact in result.facts if fact.key == "$.endpoint")
    assert network.location.start_line == 3
    assert endpoint.location.start_line == 5
    assert network.dimension == endpoint.dimension == "PERMISSION"
