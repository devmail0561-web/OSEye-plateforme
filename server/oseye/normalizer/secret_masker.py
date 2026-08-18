"""Secret masker — redact credentials from cmdline strings before normalisation."""

from __future__ import annotations

import re

PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        # SEC-MASK-001: negative lookbehind (?<!\w) prevents matching mid-word
        # occurrences (e.g. "x_password_hash" should not be masked).
        re.compile(r"(?i)(?<!\w)(password|passwd|secret|token|key|api[_-]?key)\s*[=:]\s*[^\s,;'\\]+"),
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
        re.compile(r"(?i)(?<!\w)(-p(?:ass(?:word|wd)?)?|--password)(?:[ =])([^\s,;'\\]+)"),
        r"\1***",
    ),
    (
        re.compile(r"(?i)(Authorization:\s*Bearer\s+)[^\s,;'\\]+"),
        r"\1***",
    ),
    (
        # SEC-MASK-002: HTTP Basic authentication credentials.
        re.compile(r"(?i)(Authorization:\s*Basic\s+)[^\s,;'\\]+"),
        r"\1***",
    ),
    (
        # SEC-MASK-003: token-based Authorization header (e.g. DRF Token auth).
        re.compile(r"(?i)(Authorization:\s*Token\s+)[^\s,;'\\]+"),
        r"\1***",
    ),
    (
        # SEC-MASK-004: X-Api-Key header (common REST API key header).
        re.compile(r"(?i)(X-Api-Key:\s*)[^\s,;'\\]+"),
        r"\1***",
    ),
    (
        # SEC-MASK-005: X-Auth-Token header (used by OpenStack and others).
        re.compile(r"(?i)(X-Auth-Token:\s*)[^\s,;'\\]+"),
        r"\1***",
    ),
]


def mask(text: str) -> str:
    """Redact secrets from *text* and return the sanitised string."""
    for pattern, replacement in PATTERNS:
        text = pattern.sub(replacement, text)
    return text
