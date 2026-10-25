#!/usr/bin/env python3
"""Redact common secret forms from CI text outputs before release publication."""
import json
import math
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
    ("sensitive_query_value", re.compile(r"(?i)([?&](?:token|partner|access_token|refresh_token|api[_-]?key|key|secret|auth|signature)=)[^\s\"'<>]+"), r"\1<REDACTED>"),
    ("btc_ltc_base58_address", re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|[LM][a-km-zA-HJ-NP-Z1-9]{25,34})\b"), "<REDACTED_CRYPTO_ADDRESS>"),
    ("btc_bech32_address", re.compile(r"(?i)\bbc1[ac-hj-np-z02-9]{10,70}\b"), "<REDACTED_BTC_ADDRESS>"),
    ("ltc_bech32_address", re.compile(r"(?i)\bltc1[ac-hj-np-z02-9]{10,70}\b"), "<REDACTED_LTC_ADDRESS>"),
    ("evm_wallet_address", re.compile(r"(?i)\b0x[a-f0-9]{40}\b"), "<REDACTED_EVM_ADDRESS>"),
    ("dogecoin_base58_address", re.compile(r"\bD[1-9A-HJ-NP-Za-km-z]{25,34}\b"), "<REDACTED_DOGE_ADDRESS>"),
    ("dash_base58_address", re.compile(r"\bX[1-9A-HJ-NP-Za-km-z]{25,34}\b"), "<REDACTED_DASH_ADDRESS>"),
    ("xrp_base58_address", re.compile(r"\br[1-9A-HJ-NP-Za-km-z]{24,34}\b"), "<REDACTED_XRP_ADDRESS>"),
    ("monero_base58_address", re.compile(r"\b[48][1-9A-HJ-NP-Za-km-z]{94,105}\b"), "<REDACTED_XMR_ADDRESS>"),
    ("stellar_address", re.compile(r"\bG[A-Z2-7]{55}\b"), "<REDACTED_XLM_ADDRESS>"),
    ("ton_address", re.compile(r"\b(?:EQ|UQ)[A-Za-z0-9_-]{40,60}\b"), "<REDACTED_TON_ADDRESS>"),
    ("bch_cashaddr", re.compile(r"(?i)\b(?:bitcoincash:)?[qp][a-z0-9]{40,60}\b"), "<REDACTED_BCH_ADDRESS>"),
    ("zcash_base58_address", re.compile(r"\bt[13][1-9A-HJ-NP-Za-km-z]{30,40}\b"), "<REDACTED_ZEC_ADDRESS>"),
    ("long_alphanumeric_literal", re.compile(r"\b[A-Za-z0-9]{26,128}\b"), "<REDACTED_LONG_TOKEN>"),
    ("url_query", re.compile(r"(?i)(https?://[^\s\"'<>?]+)\?[^\s\"'<>#]+"), r"\1?<REDACTED_QUERY>"),
]


def redact_opaque_literals(text):
    """Mask long high-entropy C literals that may contain unlabelled credentials."""
    pattern = re.compile(r'"((?:\\.|[^"\\])*)"')
    redacted = 0

    def replace(match):
        nonlocal redacted
        value = match.group(1)
        if len(value) < 32:
            return match.group(0)
        counts = {}
        for char in value:
            counts[char] = counts.get(char, 0) + 1
        length = len(value)
        entropy = -sum((count / length) * math.log2(count / length)
                       for count in counts.values())
        if entropy >= 4.2:
            redacted += 1
            return f'"<REDACTED_OPAQUE_LITERAL:{length}>"'
        return match.group(0)

    return pattern.sub(replace, text), redacted


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
        if path.suffix.lower() == ".c":
            text, count = redact_opaque_literals(text)
            if count:
                file_counts["opaque_high_entropy_literal"] = count
        if file_counts:
            path.write_text(text, encoding="utf-8")
            counts[path.name] = file_counts
    summary = {"files_redacted": len(counts), "redactions_by_file": counts,
               "rules": [label for label, _, _ in RULES] + ["opaque_high_entropy_literal"]}
    out = root / "redaction-summary.json"
    out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
