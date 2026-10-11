"""Output-side safety helpers. Every Excel/CSV export must pass untrusted values through these."""

from __future__ import annotations

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def spreadsheet_safe(value):
    """Neutralise spreadsheet formula injection (OWASP CSV injection guidance): a string that
    starts with a formula character gets a leading apostrophe, so Excel/LibreOffice treat it
    as text. Numbers and other types pass through unchanged."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value
