"""
Unit tests for normalizers.unicode_decoder

Run with: pytest waf/tests_normalizers/test_unicode_decoder.py -v
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from waf.normalizers.unicode_decoder import normalize


def test_zero_width_chars_stripped():
    payload = "SEL\u200bECT * FROM users"
    result = normalize(payload)
    assert result.value == "SELECT * FROM users"
    assert result.had_zero_width_chars


def test_js_unicode_escape_decoded():
    result = normalize("\\u0053\\u0045\\u004c\\u0045\\u0043\\u0054")
    assert result.value == "SELECT"
    assert result.had_js_escapes


def test_js_unicode_escape_with_braces():
    result = normalize("\\u{53}\\u{45}\\u{4c}\\u{45}\\u{43}\\u{54}")
    assert result.value == "SELECT"


def test_nfkc_normalizes_fullwidth_chars():
    fullwidth = "\uff33\uff25\uff2c\uff25\uff23\uff34"
    result = normalize(fullwidth)
    assert result.value == "SELECT"


def test_mixed_script_detected():
    payload = "p\u0430ssword"
    result = normalize(payload)
    assert result.had_mixed_script


def test_no_mixed_script_for_plain_ascii():
    result = normalize("password123")
    assert not result.had_mixed_script


def test_no_false_positive_on_clean_input():
    result = normalize("hello world")
    assert result.value == "hello world"
    assert not result.had_zero_width_chars
    assert not result.had_js_escapes
    assert not result.had_mixed_script


def test_combined_tricks():
    payload = "\\u0053EL\u200bECT"
    result = normalize(payload)
    assert result.value == "SELECT"