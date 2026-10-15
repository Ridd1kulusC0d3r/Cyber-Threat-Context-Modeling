#!/usr/bin/env python3
"""Public text guard; matching values are never printed."""
from pathlib import Path
import re
import subprocess
import sys
root = Path(__file__).resolve().parents[1]
brand = "cla" + "vis"
patterns = {
    "organization reference": re.compile(brand, re.I),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "AWS access key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "GitHub token": re.compile(r"\b(?:ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{20,}\b"),
    "private hostname": re.compile(r"https?://[^\s/'\"]+\.(?:internal|corp|local)(?:[:/]|$)", re.I),
}
files = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True).stdout
failures = []
for raw in files.split(b"\0"):
    if not raw:
        continue
    rel = raw.decode("utf-8", "surrogateescape")
    p = root / rel
    if p.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".zip", ".pdf"} or not p.is_file():
        continue
    try:
        data = p.read_text(encoding="utf-8")
    except (UnicodeError, OSError):
        continue
    for label, pattern in patterns.items():
        if pattern.search(data):
            failures.append((rel, label))
for path, label in failures:
    print(f"BLOCKED {path}: {label} (matching value suppressed)")
print(f"Public-data guard: {len(failures)} finding(s).")
sys.exit(bool(failures))
