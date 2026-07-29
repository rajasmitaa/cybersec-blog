"""
Unit tests for services.request_parser

Run with: pytest waf/tests_services/test_request_parser.py -v
"""

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from waf.services.request_parser import (
    parse_request,
    get_client_ip,
    get_uploaded_filenames,
    get_json_body,
)


class FakeFile:
    def __init__(self, name):
        self.name = name


class FakeFiles:
    def __init__(self, mapping):
        self._mapping = mapping  # dict[str, list[FakeFile]]

    def lists(self):
        return list(self._mapping.items())


class FakeRequest:
    def __init__(
        self,
        path="/",
        method="GET",
        GET=None,
        POST=None,
        COOKIES=None,
        headers=None,
        META=None,
        FILES=None,
        body=b"",
    ):
        self.path = path
        self.method = method
        self.GET = GET or {}
        self.POST = POST or {}
        self.COOKIES = COOKIES or {}
        self.headers = headers or {}
        self.META = META or {}
        self.FILES = FakeFiles(FILES or {})
        self.body = body

    def build_absolute_uri(self):
        return f"http://testserver{self.path}"


def test_parses_basic_get_request():
    request = FakeRequest(path="/search/", method="GET", GET={"q": "test"})
    parsed = parse_request(request)
    assert parsed.method == "GET"
    assert parsed.path == "/search/"
    assert parsed.query_params == {"q": "test"}


def test_client_ip_prefers_x_forwarded_for():
    request = FakeRequest(META={"HTTP_X_FORWARDED_FOR": "1.2.3.4, 5.6.7.8", "REMOTE_ADDR": "9.9.9.9"})
    assert get_client_ip(request) == "1.2.3.4"


def test_client_ip_falls_back_to_remote_addr():
    request = FakeRequest(META={"REMOTE_ADDR": "9.9.9.9"})
    assert get_client_ip(request) == "9.9.9.9"


def test_client_ip_empty_when_nothing_present():
    request = FakeRequest(META={})
    assert get_client_ip(request) == ""


def test_post_data_flattened():
    request = FakeRequest(method="POST", POST={"username": "bob", "password": "hunter2"})
    parsed = parse_request(request)
    assert parsed.post_data == {"username": "bob", "password": "hunter2"}


def test_cookies_flattened():
    request = FakeRequest(COOKIES={"session": "abc123"})
    parsed = parse_request(request)
    assert parsed.cookies == {"session": "abc123"}


def test_headers_flattened():
    request = FakeRequest(headers={"User-Agent": "sqlmap/1.0"})
    parsed = parse_request(request)
    assert parsed.headers == {"User-Agent": "sqlmap/1.0"}


def test_valid_json_body_parsed():
    body = json.dumps({"key": "value"}).encode()
    request = FakeRequest(body=body)
    assert get_json_body(request) == {"key": "value"}


def test_invalid_json_body_returns_none():
    request = FakeRequest(body=b"not json at all {{{")
    assert get_json_body(request) is None


def test_json_array_body_returns_none():
    # top-level array, not a dict -- treated as unusable for our purposes
    request = FakeRequest(body=b"[1, 2, 3]")
    assert get_json_body(request) is None


def test_empty_body_returns_none():
    request = FakeRequest(body=b"")
    assert get_json_body(request) is None


def test_uploaded_filenames_across_fields():
    files = {
        "avatar": [FakeFile("photo.png")],
        "attachments": [FakeFile("doc.pdf"), FakeFile("shell.php")],
    }
    request = FakeRequest(FILES=files)
    names = get_uploaded_filenames(request)
    assert set(names) == {"photo.png", "doc.pdf", "shell.php"}


def test_no_files_returns_empty_list():
    request = FakeRequest()
    assert get_uploaded_filenames(request) == []


def test_content_type_extracted():
    request = FakeRequest(META={"CONTENT_TYPE": "application/json"})
    parsed = parse_request(request)
    assert parsed.content_type == "application/json"


def test_full_url_uses_build_absolute_uri():
    request = FakeRequest(path="/blog/post/1/")
    parsed = parse_request(request)
    assert parsed.full_url == "http://testserver/blog/post/1/"


def test_malformed_request_never_raises():
    # a request missing almost everything real Django provides
    class BareRequest:
        pass

    request = BareRequest()
    parsed = parse_request(request)  # should not raise
    assert parsed.ip == ""
    assert parsed.method == ""
    assert parsed.files == []
    assert parsed.json_body is None
