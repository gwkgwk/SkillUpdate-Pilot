"""Read local Git objects without checkout, filters, imports, or Skill execution."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from skillupdate.marketplace.models import safe_path


class GitHistory:
    def __init__(self, repository: str | Path):
        self.repository = Path(repository).resolve(strict=True)
        self.env = {
            "PATH": os.defpath,
            "LANG": "C.UTF-8",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
        }
        shallow = self.git("rev-parse", "--is-shallow-repository").strip()
        if shallow != b"false":
            raise ValueError("shallow repositories cannot establish complete history")

    def git(self, *arguments: str) -> bytes:
        return subprocess.run(
            [
                "git",
                "--no-replace-objects",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
                str(self.repository),
                *arguments,
            ],
            env=self.env,
            capture_output=True,
            check=True,
            timeout=30,
        ).stdout

    def resolve(self, revision: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision):
            raise ValueError("offline history requires an explicit full commit SHA")
        sha = self.git("rev-parse", "--verify", revision + "^{commit}").decode().strip()
        if sha != revision:
            raise ValueError("resolved commit differs from requested SHA")
        return sha

    def commits(self, head: str, max_commits: int = 1000) -> list[str]:
        sha = self.resolve(head)
        commits = (
            self.git("rev-list", "--first-parent", "--reverse", sha)
            .decode()
            .splitlines()
        )
        if len(commits) > max_commits:
            raise ValueError("history limit exceeded; no silent truncation")
        return commits

    def directory(self, commit: str, skill_path: str):
        safe_path(skill_path)
        tree = self.git("ls-tree", "-r", "-z", "--full-tree", commit, "--", skill_path)
        result = []
        prefix = "" if skill_path == "." else skill_path + "/"
        for record in tree.split(b"\0"):
            if not record:
                continue
            metadata, raw_path = record.split(b"\t", 1)
            mode, kind, oid = metadata.decode().split()
            full = raw_path.decode("utf-8", errors="strict")
            if not full.startswith(prefix):
                continue
            relative = full[len(prefix) :]
            safe_path(relative)
            result.append((relative, mode, kind, oid))
        return result

    def blob(self, oid: str, max_bytes: int) -> bytes:
        size = int(self.git("cat-file", "-s", oid))
        if size > max_bytes:
            raise ValueError("Git blob exceeds snapshot byte budget")
        return self.git("cat-file", "blob", oid)
