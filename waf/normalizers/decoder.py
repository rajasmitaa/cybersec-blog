"""
decoder.py

Orchestrates url_decoder, unicode_decoder, and base64_decoder into a
single "decode this value as far as it will go" pipeline.

Why interleave instead of running each decoder once in sequence?
Because encodings are often stacked in ways that only reveal each
other one layer at a time. E.g. a payload that's base64-encoded, and
the base64 *output* is itself URL-encoded, and that URL-encoded
output contains JS unicode escapes. Running url-decode -> base64 ->
unicode once, in a fixed order, misses combinations. Instead we loop:
apply all three, check if anything changed, repeat until stable (or a
safety cap is hit).

This is the single function attack-detector modules (Member 2) should
call before running their regex library against user input.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .url_decoder import decode as url_decode, looks_percent_encoded
from .unicode_decoder import normalize as unicode_normalize
from .base64_decoder import decode_if_base64

DEFAULT_MAX_ITERATIONS = 5


@dataclass
class FullDecodeResult:
    original: str
    value: str                  # fully decoded/normalized value
    iterations: int
    layers: list[str] = field(default_factory=list)
    multiply_encoded: bool = False
    had_zero_width_chars: bool = False
    had_js_escapes: bool = False
    had_mixed_script: bool = False
    was_base64: bool = False

    @property
    def suspicious(self) -> bool:
        """Cheap heuristic: any of these signals alone can be benign,
        but their presence is worth surfacing to detectors/scoring even
        before pattern matching runs (e.g. "input was double-encoded"
        is itself a mild risk signal)."""
        return (
            self.multiply_encoded
            or self.had_zero_width_chars
            or self.had_js_escapes
            or self.had_mixed_script
        )

    @property
    def reason_summary(self) -> str:
        """Human-readable summary suitable for a detector's `reason`
        field, e.g. "double URL-encoded, zero-width chars stripped"."""
        return ", ".join(self.layers) if self.layers else "no decoding applied"


def decode_fully(
    value: str,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    plus_as_space: bool = False,
) -> FullDecodeResult:
    """Run url/base64/unicode decoding in a loop until the value stops
    changing or `max_iterations` is reached.

    Args:
        value: raw input (a query param, header value, cookie, form
            field, etc.)
        max_iterations: safety cap against decode bombs / pathological
            input that could otherwise loop indefinitely.
        plus_as_space: pass True for form-urlencoded / query string
            values, False for path segments.
    """
    current = value
    layers: list[str] = []
    total_url_passes = 0
    had_zero_width = False
    had_js_escapes = False
    had_mixed_script = False
    was_base64 = False
    iterations_run = 0

    for i in range(max_iterations):
        iterations_run += 1
        changed_this_round = False

        # 1. URL-decode (may itself take multiple passes internally)
        if looks_percent_encoded(current):
            url_result = url_decode(current, max_passes=1, plus_as_space=plus_as_space)
            if url_result.value != current:
                current = url_result.value
                total_url_passes += 1
                changed_this_round = True

        # 2. Unicode normalize (JS escapes, zero-width strip, NFKC)
        uni_result = unicode_normalize(current)
        if uni_result.value != current:
            current = uni_result.value
            changed_this_round = True
        had_zero_width = had_zero_width or uni_result.had_zero_width_chars
        had_js_escapes = had_js_escapes or uni_result.had_js_escapes
        had_mixed_script = had_mixed_script or uni_result.had_mixed_script
        layers.extend(uni_result.notes)

        # 3. Whole-value base64 decode (only if the *entire* value is
        #    base64 -- embedded substrings are handled separately by
        #    request_normalizer for body/param scanning)
        b64_result = decode_if_base64(current)
        if b64_result.is_base64 and b64_result.printable and b64_result.decoded is not None:
            current = b64_result.decoded
            was_base64 = True
            changed_this_round = True
            layers.append("base64-decoded")

        if not changed_this_round:
            break

    if total_url_passes:
        layers.insert(0, f"url-decoded x{total_url_passes}")

    return FullDecodeResult(
        original=value,
        value=current,
        iterations=iterations_run,
        layers=layers,
        multiply_encoded=total_url_passes > 1,
        had_zero_width_chars=had_zero_width,
        had_js_escapes=had_js_escapes,
        had_mixed_script=had_mixed_script,
        was_base64=was_base64,
    )
