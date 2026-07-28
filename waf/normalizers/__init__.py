"""
normalizers
===========

Decoding/normalization pipeline for the WAF. Run request data through
this BEFORE handing it to attack detectors (SQLi, XSS, etc.) -- it
unwinds URL encoding, base64, and Unicode tricks attackers use to
sneak payloads past pattern-matching.

Public API:
    - decode_fully(value): decode a single string through all layers
    - normalize_request(request): decode an entire Django request
    - normalize_value(value): convenience alias for a single ad-hoc string
"""

from .decoder import decode_fully, FullDecodeResult
from .request_normalizer import normalize_request, normalize_value, NormalizedRequest, NormalizedField
from .url_decoder import decode as url_decode
from .base64_decoder import decode_if_base64, find_base64_substrings
from .unicode_decoder import normalize as unicode_normalize

__all__ = [
    "decode_fully",
    "FullDecodeResult",
    "normalize_request",
    "normalize_value",
    "NormalizedRequest",
    "NormalizedField",
    "url_decode",
    "decode_if_base64",
    "find_base64_substrings",
    "unicode_normalize",
]
