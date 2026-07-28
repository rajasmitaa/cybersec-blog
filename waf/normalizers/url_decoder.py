"""
url_decoder.py

Percent-decoding (URL decoding) with support for detecting and
unwinding *nested* encoding — a classic WAF bypass technique where an
attacker encodes a payload more than once so a filter that only
decodes a single layer never sees the real content.

Example bypass this defends against:
    Attacker sends:  %2527%2520OR%25201%253D1   (double-encoded)
    Single decode:   %27%20OR%201%3D1
    Full decode:     ' OR 1=1

If a detector only ran a single decode pass, it would see "%27 OR
1%3D1" -- no obvious SQL syntax -- and miss the attack entirely.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import unquote, unquote_plus

# Matches a % followed by two hex digits, OR IIS-style %uXXXX unicode escapes
_PERCENT_ENCODING_RE = re.compile(r"%[0-9A-Fa-f]{2}|%u[0-9A-Fa-f]{4}")

DEFAULT_MAX_PASSES = 5


@dataclass
class DecodeResult:
    value: str
    passes_applied: int
    layers: list[str] = field(default_factory=list)  # human-readable trace, e.g. ["url-decode pass 1", ...]

    @property
    def was_encoded(self) -> bool:
        return self.passes_applied > 0

    @property
    def multiply_encoded(self) -> bool:
        """True if the value was encoded more than once -- itself a
        signal worth flagging to detectors, since legitimate clients
        rarely double-encode."""
        return self.passes_applied > 1


def _decode_iis_unicode_escapes(value: str) -> str:
    """Decode IIS/ASP-style %uXXXX escapes (not covered by urllib)."""
    return re.sub(
        r"%u([0-9A-Fa-f]{4})",
        lambda m: chr(int(m.group(1), 16)),
        value,
    )


def _single_pass_decode(value: str, plus_as_space: bool) -> str:
    value = _decode_iis_unicode_escapes(value)
    return unquote_plus(value) if plus_as_space else unquote(value)


def decode(value: str, max_passes: int = DEFAULT_MAX_PASSES, plus_as_space: bool = False) -> DecodeResult:
    """Repeatedly percent-decode `value` until it stops changing or
    `max_passes` is hit (safety cap against decode bombs / infinite
    loops on adversarial input).

    Args:
        value: the raw string to decode.
        max_passes: hard cap on decode iterations.
        plus_as_space: treat '+' as a space (correct for
            application/x-www-form-urlencoded bodies and query
            strings, but WRONG for path segments where '+' is literal).
    """
    current = value
    layers: list[str] = []

    for i in range(max_passes):
        # Even with no %XX sequences left, a plus_as_space pass may
        # still need to run once (form-encoded '+' has no % marker).
        has_percent_encoding = bool(_PERCENT_ENCODING_RE.search(current))
        has_plus_to_decode = plus_as_space and "+" in current
        if not has_percent_encoding and not has_plus_to_decode:
            break
        decoded = _single_pass_decode(current, plus_as_space)
        if decoded == current:
            break
        layers.append(f"url-decode pass {i + 1}")
        current = decoded

    return DecodeResult(value=current, passes_applied=len(layers), layers=layers)


def looks_percent_encoded(value: str) -> bool:
    """Cheap pre-check so callers can skip decode() entirely for values
    that obviously contain no percent-encoding."""
    return bool(_PERCENT_ENCODING_RE.search(value))
