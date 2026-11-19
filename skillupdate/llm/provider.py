"""Replaceable provider protocol and a dependency-free OpenAI-compatible API."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Protocol

from pydantic import ValidationError

from .models import ProviderResponse, TokenUsage


class ProviderError(RuntimeError):
    def __init__(self, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.retryable = retryable


class LLMProvider(Protocol):
    def complete(
        self,
        *,
        messages: list[dict[str, str]],
        model: str,
        timeout_seconds: float,
        max_output_tokens: int,
    ) -> ProviderResponse: ...


class OpenAICompatibleProvider:
    """Minimal JSON API adapter; the API key is read only when a call is made."""

    def __init__(
        self,
        *,
        endpoint: str = "https://api.openai.com/v1/chat/completions",
        api_key_env: str = "OPENAI_API_KEY",
        max_tokens_field: str = "max_completion_tokens",
        extra_request_fields: Mapping[str, object] | None = None,
    ) -> None:
        if max_tokens_field not in {"max_completion_tokens", "max_tokens"}:
            raise ValueError("unsupported max token field")
        reserved = {
            "model",
            "messages",
            "max_completion_tokens",
            "max_tokens",
            "response_format",
        }
        overlap = reserved & set(extra_request_fields or {})
        if overlap:
            raise ValueError(f"extra request fields override reserved keys: {sorted(overlap)}")
        self.endpoint = endpoint
        self.api_key_env = api_key_env
        self.max_tokens_field = max_tokens_field
        self.extra_request_fields = dict(extra_request_fields or {})

    def complete(
        self,
        *,
        messages: list[dict[str, str]],
        model: str,
        timeout_seconds: float,
        max_output_tokens: int,
    ) -> ProviderResponse:
        api_key = os.environ.get(self.api_key_env)
        if not api_key:
            raise ProviderError(
                f"required API key environment variable is not set: {self.api_key_env}",
                retryable=False,
            )
        payload = {
            "model": model,
            "messages": messages,
            self.max_tokens_field: max_output_tokens,
            "response_format": {"type": "json_object"},
        }
        payload.update(self.extra_request_fields)
        body = json.dumps(payload).encode()
        request = urllib.request.Request(
            self.endpoint,
            data=body,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                raw = json.loads(response.read().decode("utf-8"))
                request_id = response.headers.get("x-request-id")
        except urllib.error.HTTPError as exc:
            retryable = exc.code == 429 or exc.code >= 500
            raise ProviderError(f"provider HTTP status {exc.code}", retryable=retryable) from exc
        except (TimeoutError, urllib.error.URLError) as exc:
            raise ProviderError("provider request failed or timed out", retryable=True) from exc
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderError("provider returned invalid transport JSON", retryable=False) from exc
        try:
            usage = raw.get("usage", {})
            return ProviderResponse(
                text=raw["choices"][0]["message"]["content"],
                model=raw.get("model", model),
                request_id=request_id or raw.get("id"),
                usage=TokenUsage(
                    input_tokens=usage.get("prompt_tokens", 0),
                    output_tokens=usage.get("completion_tokens", 0),
                    total_tokens=usage.get(
                        "total_tokens",
                        usage.get("prompt_tokens", 0)
                        + usage.get("completion_tokens", 0),
                    ),
                    estimated=not bool(usage),
                ),
                raw=raw,
            )
        except (KeyError, IndexError, TypeError, ValidationError) as exc:
            raise ProviderError("provider response schema is invalid", retryable=False) from exc
