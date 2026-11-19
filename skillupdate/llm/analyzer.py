"""Evidence-constrained LLM analyzer with retries, limits, and durable audits."""

from __future__ import annotations

import json
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from .models import (
    AnalysisPackage,
    AnalyzerResult,
    ProviderResponse,
    SecurityAssessment,
    TokenUsage,
    unknown_assessment,
)
from .prompts import PROMPT_VERSION, SYSTEM_PROMPT, build_user_prompt
from .provider import LLMProvider, ProviderError


@dataclass(frozen=True)
class AnalyzerConfig:
    model: str
    audit_root: Path
    timeout_seconds: float = 30.0
    max_retries: int = 2
    retry_backoff_seconds: float = 0.25
    min_request_interval_seconds: float = 0.0
    max_input_tokens: int = 100_000
    max_output_tokens: int = 2_000

    def __post_init__(self) -> None:
        if not self.model.strip():
            raise ValueError("model must not be empty")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_retries < 0 or self.retry_backoff_seconds < 0:
            raise ValueError("retry configuration must not be negative")
        if self.min_request_interval_seconds < 0:
            raise ValueError("request interval must not be negative")
        if self.max_input_tokens <= 0 or self.max_output_tokens <= 0:
            raise ValueError("token budgets must be positive")


class RateLimiter:
    def __init__(
        self,
        minimum_interval: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.minimum_interval = minimum_interval
        self.clock = clock
        self.sleep = sleep
        self._lock = threading.Lock()
        self._last_request: float | None = None

    def wait(self) -> None:
        with self._lock:
            now = self.clock()
            if self._last_request is not None:
                delay = self.minimum_interval - (now - self._last_request)
                if delay > 0:
                    self.sleep(delay)
                    now = self.clock()
            self._last_request = now


class LLMSecurityAnalyzer:
    def __init__(
        self,
        provider: LLMProvider,
        config: AnalyzerConfig,
        *,
        sleep: Callable[[float], None] = time.sleep,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self.provider = provider
        self.config = config
        self.sleep = sleep
        self.rate_limiter = rate_limiter or RateLimiter(
            config.min_request_interval_seconds, sleep=sleep
        )

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        return max(1, (len(text) + 3) // 4)

    def _audit_directory(self, update_id: str) -> Path:
        safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in update_id)
        run_id = f"{time.time_ns()}-{uuid.uuid4().hex[:8]}"
        directory = self.config.audit_root / safe_id / run_id
        directory.mkdir(parents=True, exist_ok=False)
        return directory

    @staticmethod
    def _write_json(path: Path, payload: object) -> None:
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )
        temporary.replace(path)

    @staticmethod
    def _validate_grounding(
        assessment: SecurityAssessment, package: AnalysisPackage
    ) -> list[str]:
        catalog = {item.evidence_id: item for item in package.evidence_catalog}
        path_ids = {item["path_id"] for item in package.new_risk_paths}
        cited_ids = {item.evidence_id for item in assessment.evidence_locations}
        for behavior in [*assessment.new_behaviors, *assessment.historical_behaviors]:
            cited_ids.update(behavior.evidence_ids)
        errors: list[str] = []
        missing = cited_ids - set(catalog)
        if missing:
            errors.append(f"unknown evidence IDs: {sorted(missing)}")
        for location in assessment.evidence_locations:
            item = catalog.get(location.evidence_id)
            if item and (
                location.file != item.file
                or location.start_line != item.start_line
                or location.end_line != item.end_line
            ):
                errors.append(f"location does not match catalog: {location.evidence_id}")
        expected_files = sorted(
            {catalog[item].file for item in cited_ids if item in catalog}
        )
        if sorted(set(assessment.evidence_files)) != expected_files:
            errors.append("evidence_files do not exactly match cited catalog entries")
        unknown_paths = set(assessment.attack_paths) - path_ids
        if unknown_paths:
            errors.append(f"unknown attack path IDs: {sorted(unknown_paths)}")
        makes_risk_claim = bool(
            assessment.risk_types
            or assessment.new_behaviors
            or assessment.historical_behaviors
            or assessment.attack_paths
            or assessment.snapshot_status in {"SUSPICIOUS", "MALICIOUS"}
            or assessment.update_impact
            not in {"NO_NEW_RISK", "RISK_REMOVED", "UNKNOWN"}
        )
        if makes_risk_claim and not cited_ids:
            errors.append("risk claims require cited evidence")
        return errors

    def analyze(self, package: AnalysisPackage) -> AnalyzerResult:
        started = time.perf_counter()
        user_prompt = build_user_prompt(package)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]
        estimated_input = self._estimate_tokens(SYSTEM_PROMPT + user_prompt)
        audit_directory = self._audit_directory(package.update_id)
        self._write_json(
            audit_directory / "request.json",
            {
                "prompt_version": PROMPT_VERSION,
                "requested_model": self.config.model,
                "timeout_seconds": self.config.timeout_seconds,
                "max_output_tokens": self.config.max_output_tokens,
                "messages": messages,
            },
        )
        response: ProviderResponse | None = None
        errors: list[str] = []
        attempts = 0
        if estimated_input > self.config.max_input_tokens:
            errors.append(
                f"estimated input token budget exceeded: {estimated_input} > "
                f"{self.config.max_input_tokens}"
            )
        else:
            for attempt in range(self.config.max_retries + 1):
                attempts += 1
                self.rate_limiter.wait()
                try:
                    response = self.provider.complete(
                        messages=messages,
                        model=self.config.model,
                        timeout_seconds=self.config.timeout_seconds,
                        max_output_tokens=self.config.max_output_tokens,
                    )
                    break
                except ProviderError as exc:
                    errors.append(str(exc))
                    if not exc.retryable or attempt == self.config.max_retries:
                        break
                    self.sleep(self.config.retry_backoff_seconds * (2**attempt))
                except (OSError, TimeoutError, ValueError) as exc:
                    errors.append(f"unexpected provider failure: {type(exc).__name__}")
                    break

        status = "PROVIDER_ERROR"
        assessment = unknown_assessment("LLM provider unavailable or budget exceeded")
        raw_payload: dict[str, object] = {"response": None, "errors": errors}
        usage = TokenUsage(
            input_tokens=estimated_input,
            output_tokens=0,
            total_tokens=estimated_input,
            estimated=True,
        )
        if response is not None:
            usage = response.usage
            raw_payload = {
                "text": response.text,
                "model": response.model,
                "request_id": response.request_id,
                "usage": response.usage.model_dump(mode="json"),
                "provider_response": response.raw,
            }
            if response.usage.output_tokens > self.config.max_output_tokens:
                errors.append(
                    "provider output token budget exceeded: "
                    f"{response.usage.output_tokens} > {self.config.max_output_tokens}"
                )
                assessment = unknown_assessment(
                    "Provider response exceeded the configured output budget"
                )
            else:
                try:
                    decoded = json.loads(response.text)
                except json.JSONDecodeError as exc:
                    status = "INVALID_JSON"
                    errors.append(f"invalid JSON: {exc.msg}")
                    assessment = unknown_assessment("Model response was not valid JSON")
                else:
                    try:
                        candidate = SecurityAssessment.model_validate(decoded)
                    except ValidationError as exc:
                        status = "INVALID_SCHEMA"
                        errors.extend(
                            f"invalid schema at {'.'.join(str(p) for p in item['loc'])}: {item['msg']}"
                            for item in exc.errors()
                        )
                        assessment = unknown_assessment(
                            "Model response did not match the required schema"
                        )
                    else:
                        grounding_errors = self._validate_grounding(candidate, package)
                        if grounding_errors:
                            status = "UNGROUNDED"
                            errors.extend(grounding_errors)
                            assessment = unknown_assessment(
                                "Model response cited evidence outside the supplied catalog"
                            )
                        else:
                            status = "VALID"
                            assessment = candidate
        self._write_json(audit_directory / "raw_response.json", raw_payload)
        self._write_json(
            audit_directory / "parsed_response.json",
            {
                "parse_status": status,
                "assessment": assessment.model_dump(mode="json"),
                "validation_errors": errors,
            },
        )
        return AnalyzerResult(
            update_id=package.update_id,
            requested_model=self.config.model,
            returned_model=response.model if response else None,
            parse_status=status,
            assessment=assessment,
            validation_errors=errors,
            usage=usage,
            latency_ms=(time.perf_counter() - started) * 1000,
            attempts=attempts,
            audit_directory=str(audit_directory),
        )
