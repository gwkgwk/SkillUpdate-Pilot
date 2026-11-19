"""Shared source-location helpers without cross-language parsing logic."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from pathlib import Path

from .models import SourceLocation

SECURITY_TERMS = (
    "credential",
    "secret",
    "token",
    "password",
    "network",
    "endpoint",
    "command",
    "execute",
    "permission",
    "deny",
    "allow",
    "must not",
    "do not",
    "never",
    "only",
)


def excerpt(lines: list[str], start_line: int, end_line: int) -> str:
    return "\n".join(lines[start_line - 1 : end_line])[:2000]


def location(
    *,
    snapshot: str,
    file: str,
    lines: list[str],
    start_line: int,
    end_line: int | None = None,
) -> SourceLocation:
    final_line = end_line or start_line
    start_line = max(1, start_line)
    final_line = max(start_line, final_line)
    return SourceLocation(
        snapshot=snapshot,
        file=file,
        start_line=start_line,
        end_line=final_line,
        excerpt=excerpt(lines, start_line, final_line),
    )


def stable_id(*values: str) -> str:
    return hashlib.sha256("\0".join(values).encode()).hexdigest()[:20]


def is_security_text(value: str) -> bool:
    lower = value.lower()
    return any(term in lower for term in SECURITY_TERMS)


def normalize_space(value: str) -> str:
    return " ".join(value.split())


def safe_relative_files(root: Path, max_files: int = 512) -> Iterable[Path]:
    paths = sorted(
        item for item in root.rglob("*") if item.is_file() or item.is_symlink()
    )
    if len(paths) > max_files:
        raise ValueError("HSDA file-count limit exceeded")
    for path in paths:
        if path.is_symlink():
            raise ValueError(f"HSDA rejects symlink input: {path}")
        yield path
