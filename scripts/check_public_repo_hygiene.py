#!/usr/bin/env python3
"""Fail CI when tracked public-repository files resemble private case material."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()

SAFE_EMAIL_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "users.noreply.github.com",
    "noreply.github.com",
    "github.com",
}

SAFE_IPV4_NETWORK_PREFIXES = (
    "192.0.2.",
    "198.51.100.",
    "203.0.113.",
)

TEXT_SUFFIXES = {
    ".md", ".txt", ".py", ".yaml", ".yml", ".json", ".jsonl", ".csv",
    ".toml", ".ini", ".cfg", ".conf", ".xml", ".html", ".ipynb",
}

EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b")
PRIVATE_IPV4_RE = re.compile(
    r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"
)
INTERNAL_DOMAIN_RE = re.compile(
    r"(?i)\b(?:[a-z0-9-]+\.)+(?:local|internal|corp)\b"
)
USER_PATH_RE = re.compile(
    r"(?:/Users/[A-Za-z0-9._-]+|/home/[A-Za-z0-9._-]+|"
    r"[A-Za-z]:\\Users\\[^\\\s]+)"
)
COLAB_INSTANCE_RE = re.compile(
    r"(?i)https?://[a-z0-9-]+(?:-[a-z0-9-]+)*\.[a-z0-9.-]*prod\.colab\.dev(?:/\S*)?"
)
AGENT_SESSION_RE = re.compile(
    r"(?i)https?://claude\.ai/(?:chat|code)/[A-Za-z0-9_/-]+"
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
)
AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GITHUB_TOKEN_RE = re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b")
SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")
GENERIC_SECRET_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|password|passwd|secret|token)\s*[:=]\s*"
    r"[\"']?[A-Za-z0-9_+/=-]{12,}"
)

# Optional local/CI denylist. Keep organization names out of this public source file.
DENYLIST = tuple(
    item.strip().lower()
    for item in os.environ.get("TCE_PUBLIC_REPO_DENYLIST", "").split(",")
    if item.strip()
)


def tracked_files() -> list[Path]:
    try:
        raw = subprocess.check_output(
            ["git", "-C", str(ROOT), "ls-files", "-z"],
            stderr=subprocess.DEVNULL,
        )
        return [
            ROOT / item.decode("utf-8")
            for item in raw.split(b"\0")
            if item
        ]
    except Exception:
        return [
            p for p in ROOT.rglob("*")
            if p.is_file() and ".git" not in p.parts
        ]


def looks_textual(path: Path) -> bool:
    return path.suffix.lower() in TEXT_SUFFIXES or path.name in {
        "README", "LICENSE", "SECURITY", "CONTRIBUTING", "ROADMAP", ".gitignore"
    }


def scan_text(path: Path, text: str) -> list[tuple[int, str, str]]:
    findings: list[tuple[int, str, str]] = []
    lines = text.splitlines()

    for lineno, line in enumerate(lines, start=1):
        lower = line.lower()

        for term in DENYLIST:
            if term in lower:
                findings.append((lineno, "denylisted-term", term))

        for match in EMAIL_RE.finditer(line):
            domain = match.group(1).lower()
            if domain not in SAFE_EMAIL_DOMAINS:
                findings.append((lineno, "email-address", match.group(0)))

        for match in PRIVATE_IPV4_RE.finditer(line):
            value = match.group(0)
            if not value.startswith(SAFE_IPV4_NETWORK_PREFIXES):
                findings.append((lineno, "private-ipv4", value))

        for label, regex in (
            ("internal-domain", INTERNAL_DOMAIN_RE),
            ("user-home-path", USER_PATH_RE),
            ("temporary-colab-url", COLAB_INSTANCE_RE),
            ("agent-session-url", AGENT_SESSION_RE),
            ("private-key", PRIVATE_KEY_RE),
            ("aws-access-key", AWS_ACCESS_KEY_RE),
            ("github-token", GITHUB_TOKEN_RE),
            ("slack-token", SLACK_TOKEN_RE),
            ("hardcoded-secret", GENERIC_SECRET_RE),
        ):
            for match in regex.finditer(line):
                findings.append((lineno, label, match.group(0)))

    return findings


def main() -> int:
    failures: list[tuple[str, int, str, str]] = []

    for path in tracked_files():
        if path.resolve() == SELF or not path.exists() or not looks_textual(path):
            continue

        try:
            raw = path.read_bytes()
        except OSError:
            continue

        if b"\0" in raw or len(raw) > 5_000_000:
            continue

        text = raw.decode("utf-8", errors="ignore")
        for lineno, label, value in scan_text(path, text):
            failures.append((
                str(path.relative_to(ROOT)),
                lineno,
                label,
                value[:180],
            ))

    if failures:
        print("PUBLIC_REPO_HYGIENE_FAILED")
        for path, lineno, label, value in failures:
            print(f"{path}:{lineno}: {label}: {value}")
        print(
            "\nReplace organization-specific values with synthetic/reserved examples. "
            "Keep private case material outside the public repository."
        )
        return 2

    print("PUBLIC_REPO_HYGIENE_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
