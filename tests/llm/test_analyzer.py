from __future__ import annotations

import json
from pathlib import Path

from conftest import FakeProvider, ProviderError, assessment_for

from skillupdate.llm import (
    AnalyzerConfig,
    LLMSecurityAnalyzer,
    OpenAICompatibleProvider,
    RateLimiter,
)


def analyzer(provider, tmp_path: Path, **overrides):
    config = AnalyzerConfig(
        model="fake-requested-model",
        audit_root=tmp_path / "audit",
        **overrides,
    )
    return LLMSecurityAnalyzer(provider, config, sleep=lambda _: None)


def test_valid_response_is_grounded_and_audited(benign_analysis, tmp_path):
    package, _, _ = benign_analysis
    provider = FakeProvider([assessment_for(package, "BENIGN", "NO_NEW_RISK")])
    result = analyzer(provider, tmp_path).analyze(package)

    assert result.parse_status == "VALID"
    assert result.assessment.snapshot_status == "BENIGN"
    audit = Path(result.audit_directory)
    assert {item.name for item in audit.iterdir()} == {
        "request.json",
        "raw_response.json",
        "parsed_response.json",
    }
    assert json.loads((audit / "parsed_response.json").read_text())["parse_status"] == "VALID"


def test_invalid_json_fails_closed(malicious_analysis, tmp_path):
    package, _, _ = malicious_analysis
    result = analyzer(FakeProvider(["not-json"]), tmp_path).analyze(package)

    assert result.parse_status == "INVALID_JSON"
    assert result.assessment.snapshot_status == "UNKNOWN"
    assert result.assessment.update_impact == "UNKNOWN"
    assert result.assessment.verification_required is True


def test_fabricated_location_is_rejected(malicious_analysis, tmp_path):
    package, _, _ = malicious_analysis
    response = assessment_for(package, "MALICIOUS", "NEW_RISK")
    response["evidence_locations"][0]["start_line"] += 1000
    result = analyzer(FakeProvider([response]), tmp_path).analyze(package)

    assert result.parse_status == "UNGROUNDED"
    assert result.assessment.snapshot_status == "UNKNOWN"
    assert any("does not match catalog" in item for item in result.validation_errors)


def test_retry_timeout_and_usage_are_recorded(benign_analysis, tmp_path):
    package, _, _ = benign_analysis
    response = assessment_for(package, "BENIGN", "NO_NEW_RISK")
    provider = FakeProvider(
        [ProviderError("synthetic timeout", retryable=True), response]
    )
    result = analyzer(provider, tmp_path, max_retries=1).analyze(package)

    assert result.parse_status == "VALID"
    assert result.attempts == 2
    assert result.usage.total_tokens == 150
    assert len(provider.calls) == 2
    assert provider.calls[0]["timeout_seconds"] == 30.0


def test_input_and_output_budgets_fail_closed(benign_analysis, tmp_path):
    package, _, _ = benign_analysis
    response = assessment_for(package, "BENIGN", "NO_NEW_RISK")
    provider = FakeProvider([response])
    input_result = analyzer(provider, tmp_path, max_input_tokens=1).analyze(package)
    assert input_result.parse_status == "PROVIDER_ERROR"
    assert not provider.calls

    output_result = analyzer(
        FakeProvider([response]), tmp_path, max_output_tokens=10
    ).analyze(package)
    assert output_result.parse_status == "PROVIDER_ERROR"
    assert output_result.assessment.snapshot_status == "UNKNOWN"


def test_rate_limiter_enforces_minimum_interval():
    now = [10.0]
    delays = []

    def sleep(delay):
        delays.append(delay)
        now[0] += delay

    limiter = RateLimiter(2.0, clock=lambda: now[0], sleep=sleep)
    limiter.wait()
    limiter.wait()
    assert delays == [2.0]


def test_openai_provider_requires_environment_key(monkeypatch):
    monkeypatch.delenv("P13_TEST_API_KEY", raising=False)
    provider = OpenAICompatibleProvider(api_key_env="P13_TEST_API_KEY")
    try:
        provider.complete(
            messages=[],
            model="unused",
            timeout_seconds=1,
            max_output_tokens=1,
        )
    except ProviderError as exc:
        assert exc.retryable is False
        assert "P13_TEST_API_KEY" in str(exc)
    else:
        raise AssertionError("missing API key must fail before network access")


def test_provider_extra_fields_cannot_override_audited_request_fields():
    try:
        OpenAICompatibleProvider(extra_request_fields={"model": "hidden-model"})
    except ValueError as exc:
        assert "reserved keys" in str(exc)
    else:
        raise AssertionError("extra provider fields must not override the model")
