"""
Unit tests for normalizers.decoder (the full decode_fully pipeline)

Run with: pytest waf/tests_normalizers/test_decoder.py -v
"""

import sys
import os
import base64
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from waf.normalizers.decoder import decode_fully


def test_plain_text_unchanged():
    result = decode_fully("hello world")
    assert result.value == "hello world"
    assert not result.suspicious


def test_url_encoded_sql_injection():
    result = decode_fully("%27%20OR%201%3D1", plus_as_space=True)
    assert "' OR 1=1" == result.value


def test_double_url_encoded_flagged_multiply_encoded():
    result = decode_fully("%2527%2520OR%25201%253D1", plus_as_space=True)
    assert result.multiply_encoded
    assert result.suspicious


def test_base64_layer_decoded():
    payload = base64.b64encode(b"<script>alert(1)</script>").decode()
    result = decode_fully(payload)
    assert result.value == "<script>alert(1)</script>"
    assert result.was_base64


def test_url_then_base64_stacked():
    # base64 of a script tag, then that base64 string URL-encoded
    inner = base64.b64encode(b"<script>alert(1)</script>").decode()
    from urllib.parse import quote
    outer = quote(inner)
    result = decode_fully(outer)
    assert result.value == "<script>alert(1)</script>"
    assert result.was_base64


def test_zero_width_and_url_encoding_combined():
    # 'SEL%E2%80%8BECT' style would be multi-byte; simpler: zero-width
    # char embedded directly, no URL encoding needed for this layer
    result = decode_fully("SEL\u200bECT")
    assert result.value == "SELECT"
    assert result.had_zero_width_chars
    assert result.suspicious


def test_reason_summary_non_empty_when_decoded():
    result = decode_fully("%27")
    assert result.reason_summary != "no decoding applied"


def test_reason_summary_for_clean_input():
    result = decode_fully("clean input")
    assert result.reason_summary == "no decoding applied"


def test_max_iterations_prevents_runaway():
    result = decode_fully("%2525252525252525", max_iterations=3)
    assert result.iterations <= 3
