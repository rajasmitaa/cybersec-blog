"""
Unit tests for normalizers.url_decoder

Run with: pytest waf/tests_normalizers/test_url_decoder.py -v
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from waf.normalizers.url_decoder import decode, looks_percent_encoded


def test_simple_decode():
    result = decode("hello%20world")
    assert result.value == "hello world"
    assert result.was_encoded


def test_no_encoding_present():
    result = decode("hello world")
    assert result.value == "hello world"
    assert not result.was_encoded


def test_double_encoding_unwound():
    # %2527 -> %27 -> '
    result = decode("%2527")
    assert result.value == "'"
    assert result.multiply_encoded


def test_sql_injection_double_encoded_bypass():
    # ' OR 1=1 double encoded
    payload = "%2527%2520OR%25201%253D1"
    result = decode(payload)
    assert "OR" in result.value
    assert "1=1" in result.value


def test_max_passes_is_respected():
    # Something that would keep "changing" is unrealistic for real
    # percent-encoding since it converges, but max_passes caps iteration count
    result = decode("%2525252525", max_passes=2)
    assert result.passes_applied <= 2


def test_plus_as_space_false_by_default():
    result = decode("a+b")
    assert result.value == "a+b"  # '+' untouched without plus_as_space


def test_plus_as_space_true_for_form_data():
    result = decode("a+b", plus_as_space=True)
    assert result.value == "a b"


def test_iis_unicode_escape_decoded():
    result = decode("%u0027")
    assert result.value == "'"


def test_looks_percent_encoded():
    assert looks_percent_encoded("abc%20def")
    assert not looks_percent_encoded("abc def")


def test_single_pass_no_infinite_loop_on_literal_percent():
    # A literal '%' not part of valid encoding shouldn't cause issues
    result = decode("100% sure")
    assert result.value == "100% sure"
