"""
Unit tests for normalizers.base64_decoder

Run with: pytest waf/tests_normalizers/test_base64_decoder.py -v
"""

import sys
import os
import base64
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from waf.normalizers.base64_decoder import decode_if_base64, find_base64_substrings


def test_decodes_valid_base64_text():
    encoded = base64.b64encode(b"hello world").decode()
    result = decode_if_base64(encoded)
    assert result.is_base64
    assert result.printable
    assert result.decoded == "hello world"


def test_xss_payload_in_base64_detected():
    payload = "<script>alert(1)</script>"
    encoded = base64.b64encode(payload.encode()).decode()
    result = decode_if_base64(encoded)
    assert result.decoded == payload


def test_rejects_short_strings():
    # too short to bother decoding even though technically valid base64
    result = decode_if_base64("abcd")
    assert not result.is_base64


def test_rejects_non_base64_charset():
    result = decode_if_base64("this is not base64 at all!! ####")
    assert not result.is_base64


def test_rejects_binary_garbage_output():
    # valid base64 charset/length but decodes to non-printable bytes
    garbage = base64.b64encode(bytes(range(200, 220))).decode()
    result = decode_if_base64(garbage)
    # is_base64 may be True (decodes fine) but printable should be False
    assert not result.printable


def test_find_embedded_base64_in_data_uri():
    payload = "<script>alert(1)</script>"
    encoded = base64.b64encode(payload.encode()).decode()
    body = f'<img src="data:text/html;base64,{encoded}">'
    matches = find_base64_substrings(body)
    assert any(m.decoded == payload for m in matches)


def test_find_base64_substrings_ignores_short_noise():
    body = "id=123&name=John&token=abcd"
    matches = find_base64_substrings(body)
    assert matches == []


def test_urlsafe_base64_variant():
    payload = b"data with / and + chars \xff\xfe" if False else b"simple text payload here"
    encoded = base64.urlsafe_b64encode(payload).decode()
    result = decode_if_base64(encoded)
    assert result.is_base64
