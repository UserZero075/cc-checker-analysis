#!/usr/bin/env python3
"""Redact common secret forms from CI text outputs before release publication."""
import json
import re
import sys
from pathlib import Path

RULES = [
    ("private_key_pem", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "<REDACTED_PRIVATE_KEY>"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "<REDACTED_JWT>"),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"), "<REDACTED_GITHUB_TOKEN>"),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "<REDACTED_AWS_KEY>"),
    ("bearer", re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/-]{12,}={0,2}"), r"\1<REDACTED>"),
    ("secret_assignment", re.compile(r"(?i)(\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|secret|cookie)\b\s*[:=]\s*)([\"']?)([A-Za-z0-9_./+=:-]{16,})\2"), r"\1<REDACTED>"),
    ("url_query", re.compile(r"(?i)(https?://[^\s\"'<>?]+)\?[^\s\"'<>#]+"), r"\1?<REDACTED_QUERY>"),
]


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "results")
    counts = {}
    for path in sorted(root.iterdir()):
        if not path.is_file() or path.suffix.lower() not in {".c", ".txt", ".log", ".json"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        file_counts = {}
        for label, pattern, replacement in RULES:
            text, count = pattern.subn(replacement, text)
            if count:
                file_counts[label] = count
        if file_counts:
            path.write_text(text, encoding="utf-8")
            counts[path.name] = file_counts
    summary = {"files_redacted": len(counts), "redactions_by_file": counts,
               "rules": [label for label, _, _ in RULES]}
    out = root / "redaction-summary.json"
    out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
