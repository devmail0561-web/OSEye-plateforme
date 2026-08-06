"""Secret masker — redact credentials from cmdline strings before normalisation."""

from __future__ import annotations

import re

PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"(?i)(password|passwd|secret|token|key|api[_-]?key)\s*[=:]\s*\S+"),
        r"\1=***",
    ),
    (
        # -p password (with space) or -pPassword (attached, as mysql/mysqldump use)
        re.compile(r"(?i)(-p)(\s+\S+|\S+)"),
        r"\1***",
    ),
    (
        re.compile(r"(?i)(Authorization:\s*Bearer\s+)\S+"),
        r"\1***",
    ),
]


def mask(text: str) -> str:
    """Redact secrets from *text* and return the sanitised string."""
    for pattern, replacement in PATTERNS:
        text = pattern.sub(replacement, text)
    return text
