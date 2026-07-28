"""
Unit tests for normalizers.request_normalizer

Run with: pytest waf/tests_normalizers/test_request_normalizer.py -v
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from waf.normalizers.request_normalizer import normalize_request, normalize_value


class FakeRequest:
    def __init__(self, path="/", method="GET", GET=None, POST=None, COOKIES=None, headers=None):
        self.path = path
        self.method = method
        self.GET = GET or {}
        self.POST = POST or {}
        self.COOKIES = COOKIES or {}
        self.headers = headers or {}


def test_normalizes_query_params():
    request = FakeRequest(GET={"q": "%27%20OR%201%3D1"})
    normalized = normalize_request(request)
    field = normalized.get("query", "q")
    assert field is not None
    assert "OR" in field.value


def test_normalizes_post_body():
    request = FakeRequest(method="POST", POST={"comment": "SEL\u200bECT * FROM users"})
    normalized = normalize_request(request)
    field = normalized.get("body", "comment")
    assert field.value == "SELECT * FROM users"


def test_normalizes_cookies():
    request = FakeRequest(COOKIES={"session": "abc123"})
    normalized = normalize_request(request)
    field = normalized.get("cookie", "session")
    assert field.value == "abc123"


def test_normalizes_headers():
    request = FakeRequest(headers={"User-Agent": "sqlmap/1.0"})
    normalized = normalize_request(request)
    field = normalized.get("header", "User-Agent")
    assert field.value == "sqlmap/1.0"


def test_path_is_decoded():
    request = FakeRequest(path="/search/%2e%2e%2fadmin")
    normalized = normalize_request(request)
    assert "../admin" in normalized.path.value


def test_suspicious_fields_filters_correctly():
    request = FakeRequest(GET={
        "clean": "hello",
        "sneaky": "%2527%2520OR%25201%253D1",
    })
    normalized = normalize_request(request)
    suspicious_keys = {f.key for f in normalized.suspicious_fields()}
    assert "sneaky" in suspicious_keys
    assert "clean" not in suspicious_keys


def test_all_decoded_values_flattens_everything():
    request = FakeRequest(
        GET={"a": "1"},
        POST={"b": "2"},
        COOKIES={"c": "3"},
        headers={"d": "4"},
    )
    normalized = normalize_request(request)
    values = normalized.all_decoded_values()
    assert set(values) == {"1", "2", "3", "4"}


def test_none_values_are_skipped_gracefully():
    request = FakeRequest(GET={"empty": None})
    normalized = normalize_request(request)
    assert normalized.get("query", "empty") is None


def test_normalize_value_convenience_function():
    result = normalize_value("%27%20OR%201%3D1", plus_as_space=True)
    assert "OR" in result.value