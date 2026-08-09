"""Secret masker — redact credentials from cmdline strings before normalisation."""

from __future__ import annotations

import re

PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"(?i)(password|passwd|secret|token|key|api[_-]?key)\s*[=:]\s*\S+"),
        r"\1=***",
    ),
    (
        # SEC-004: only mask recognised password flags to avoid destroying forensic
        # value of flags like -path, -port, -proto, -pid, etc.
        # Matches: -p VALUE, -p=VALUE, -pass VALUE, -passwd VALUE, -password VALUE,
        #          --password VALUE / --password=VALUE.
        # The negative lookbehind (?<!\w) ensures the flag is not part of a longer word.
        # The separator (space or =) is required to distinguish the -p password flag
        # from longer flags such as -path, -port, -proto that share the -p prefix.
        re.compile(r"(?i)(?<!\w)(-p(?:ass(?:word|wd)?)?|--password)(?:[ =])(\S+)"),
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
