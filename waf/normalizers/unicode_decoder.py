"""
unicode_decoder.py

Handles Unicode-based WAF bypass tricks:

1. Compatibility normalization (NFKC): full-width / half-width forms
   and other compatibility characters that *render* identically to
   ASCII but have different code points, e.g. the full-width "S"
   (U+FF33, "S") vs ASCII "S" (U+0053). A naive regex for "SELECT"
   won't match "SELECT" typed in full-width characters.

2. Zero-width character stripping: attackers insert invisible
   characters (zero-width space U+200B, zero-width joiner U+200D,
   etc.) in the middle of blocked keywords, e.g. "SEL\u200BECT",
   to break substring/regex matches while the browser/backend still
   interprets it as "SELECT".

3. \\uXXXX and \\u{XXXX} JS-style unicode escape decoding, since
   payloads are often reflected into JS contexts and attackers encode
   them that way to dodge string-based filters.

4. Basic homoglyph flagging: characters from other scripts (Cyrillic,
   Greek) that are visually near-identical to Latin letters, commonly
   used in phishing and filter-evasion. We don't silently rewrite
   these (that would be guessing intent) -- we flag their presence so
   detectors/scoring can treat mixed-script input as suspicious.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# Zero-width / invisible characters commonly used to break up blocked keywords
_ZERO_WIDTH_CHARS = (
    "\u200b"  # zero width space
    "\u200c"  # zero width non-joiner
    "\u200d"  # zero width joiner
    "\u2060"  # word joiner
    "\ufeff"  # zero width no-break space / BOM
)
_ZERO_WIDTH_RE = re.compile(f"[{_ZERO_WIDTH_CHARS}]")

# JS-style unicode escapes: \u0041 (exactly 4 hex digits) or \u{41} (1-6, braced)
_JS_UNICODE_ESCAPE_RE = re.compile(r"\\u\{([0-9A-Fa-f]{1,6})\}|\\u([0-9A-Fa-f]{4})")

# A small, high-confidence set of Latin-lookalike characters from other
# scripts, commonly abused for homoglyph attacks. Not exhaustive --
# exhaustive confusable detection needs Unicode's full confusables
# table, but this catches the common cases cheaply.
_HOMOGLYPH_RANGES = (
    (0x0400, 0x04FF),  # Cyrillic
    (0x0370, 0x03FF),  # Greek and Coptic
)


@dataclass
class UnicodeNormalizeResult:
    value: str
    had_zero_width_chars: bool
    had_js_escapes: bool
    had_mixed_script: bool
    notes: list[str] = field(default_factory=list)


def _decode_js_escapes(value: str) -> tuple[str, bool]:
    found = False

    def _replace(match: re.Match) -> str:
        nonlocal found
        found = True
        hex_digits = match.group(1) or match.group(2)
        return chr(int(hex_digits, 16))

    result = _JS_UNICODE_ESCAPE_RE.sub(_replace, value)
    return result, found


def _strip_zero_width(value: str) -> tuple[str, bool]:
    if not _ZERO_WIDTH_RE.search(value):
        return value, False
    return _ZERO_WIDTH_RE.sub("", value), True


def _has_mixed_script(value: str) -> bool:
    """Flag strings that mix ASCII letters with lookalike characters
    from other scripts -- a strong signal of homoglyph abuse, since
    legitimate ASCII keywords (SELECT, script, etc.) have no reason
    to contain Cyrillic or Greek characters."""
    has_ascii_letter = any(c.isascii() and c.isalpha() for c in value)
    has_lookalike = any(
        any(start <= ord(c) <= end for start, end in _HOMOGLYPH_RANGES)
        for c in value
    )
    return has_ascii_letter and has_lookalike


def normalize(value: str) -> UnicodeNormalizeResult:
    """Run the full Unicode normalization pipeline: decode JS escapes,
    strip zero-width characters, apply NFKC compatibility
    normalization, and flag mixed-script (homoglyph) content."""
    notes: list[str] = []

    decoded, had_js_escapes = _decode_js_escapes(value)
    if had_js_escapes:
        notes.append("decoded \\uXXXX JS unicode escapes")

    stripped, had_zero_width = _strip_zero_width(decoded)
    if had_zero_width:
        notes.append("stripped zero-width/invisible characters")

    mixed_script = _has_mixed_script(stripped)
    if mixed_script:
        notes.append("mixed-script (possible homoglyph) content detected")

    normalized = unicodedata.normalize("NFKC", stripped)
    if normalized != stripped:
        notes.append("applied NFKC compatibility normalization")

    return UnicodeNormalizeResult(
        value=normalized,
        had_zero_width_chars=had_zero_width,
        had_js_escapes=had_js_escapes,
        had_mixed_script=mixed_script,
        notes=notes,
    )
