"""
base64_decoder.py

Detects and decodes base64-encoded content. Attackers stash payloads
(XSS, SQLi, command injection) inside base64 blobs in cookies, headers,
or POST bodies, betting that a WAF only inspects the raw (encoded)
bytes and never decodes them.

Two entry points:
    - decode_if_base64(value): whole-string decode, for values that
      are ENTIRELY base64 (e.g. a cookie whose whole value is encoded).
    - find_base64_substrings(value): scans a larger string (e.g. a
      full request body) for embedded base64 blobs, such as
      "data:text/html;base64,PHNjcmlwdD4..." inside an HTML attribute.

Both refuse to "decode" short or low-confidence matches, since almost
any short alphanumeric string is technically valid base64 -- decoding
everything would flood detectors with garbage and hurt performance.
"""

from __future__ import annotations

import re
import base64
import binascii
from dataclasses import dataclass
from typing import Optional

# Minimum length before we bother attempting a decode. Shorter strings
# have too many false-positive matches (e.g. "abcd" is valid base64
# but decoding it tells you nothing useful).
MIN_BASE64_LENGTH = 16

_BASE64_CHARSET_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_BASE64_URLSAFE_CHARSET_RE = re.compile(r"^[A-Za-z0-9\-_]+={0,2}$")

# Finds candidate base64 blobs embedded inside larger text (e.g. a
# data: URI, a JWT-like segment, or a param value inside an HTML body).
_EMBEDDED_BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


@dataclass
class Base64DecodeResult:
    original: str
    decoded: Optional[str]
    is_base64: bool
    printable: bool  # whether the decoded bytes were valid, printable text


def _looks_like_base64(value: str) -> bool:
    if len(value) < MIN_BASE64_LENGTH:
        return False
    if len(value) % 4 != 0:
        return False
    return bool(_BASE64_CHARSET_RE.match(value)) or bool(_BASE64_URLSAFE_CHARSET_RE.match(value))


def _try_decode_bytes(value: str) -> Optional[bytes]:
    for variant in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return variant(value, validate=True)
        except (binascii.Error, ValueError):
            continue
    return None


def _is_mostly_printable(raw: bytes) -> bool:
    if not raw:
        return False
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return (printable / len(text)) > 0.85


def decode_if_base64(value: str) -> Base64DecodeResult:
    """Attempt a whole-string base64 decode. Only reports success if
    the result looks like real text -- protects against false
    positives on incidental base64-charset-compatible strings."""
    stripped = value.strip()

    if not _looks_like_base64(stripped):
        return Base64DecodeResult(original=value, decoded=None, is_base64=False, printable=False)

    raw = _try_decode_bytes(stripped)
    if raw is None:
        return Base64DecodeResult(original=value, decoded=None, is_base64=False, printable=False)

    printable = _is_mostly_printable(raw)
    decoded_text = raw.decode("utf-8", errors="replace") if printable else None

    return Base64DecodeResult(
        original=value,
        decoded=decoded_text,
        is_base64=True,
        printable=printable,
    )


def find_base64_substrings(value: str, min_length: int = MIN_BASE64_LENGTH) -> list[Base64DecodeResult]:
    """Scan a larger string for embedded base64 blobs (e.g. inside a
    data: URI or a request body) and decode any that look legitimate."""
    results: list[Base64DecodeResult] = []
    for match in _EMBEDDED_BASE64_RE.finditer(value):
        candidate = match.group()
        if len(candidate) < min_length:
            continue
        result = decode_if_base64(candidate)
        if result.is_base64 and result.printable:
            results.append(result)
    return results
