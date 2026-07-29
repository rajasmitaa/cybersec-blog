"""
request_parser.py

A single, reusable utility for pulling a clean, structured view of a
Django request -- IP, URL, method, headers, cookies, GET/POST, uploaded
files, and body -- for use by any WAF component that needs raw request
data without re-deriving extraction logic (services/response_builder.py,
services/geoip.py, waf/engine.py, dashboard views, benchmarking scripts,
etc.)

This is intentionally decoupled from waf/detectors/base_detector.py:
that module's extraction helpers are detector-internal (built for
matching, normalization, and multi-signal scoring). This module is a
plain data-extraction utility with no detection logic -- it doesn't
score anything or decide if a request is malicious, it just parses.

Works with any duck-typed request object exposing the same interface
as Django's HttpRequest (.GET, .POST, .COOKIES, .headers, .FILES,
.META, .body, .method, .path) -- so it can be unit tested with a
lightweight fake instead of requiring a configured Django project.

Handles the realistic edge cases:
    - IP address behind a reverse proxy (X-Forwarded-For chain)
    - JSON body vs form-encoded body vs multipart
    - Missing/malformed data (never raises -- always returns something)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional


@dataclass
class ParsedRequest:
    ip: str
    method: str
    path: str
    full_url: str
    query_params: dict
    post_data: dict
    json_body: Optional[dict]
    cookies: dict
    headers: dict
    files: list
    content_type: str


def get_client_ip(request) -> str:
    """Best-effort real client IP, accounting for a reverse proxy.

    Checks X-Forwarded-For first (takes the leftmost address, which is
    the original client in a standard proxy chain), falling back to
    REMOTE_ADDR. Never raises -- returns "" if nothing usable is found.
    """
    try:
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "") or ""
    except Exception:
        forwarded = ""
    if forwarded:
        first_ip = forwarded.split(",")[0].strip()
        if first_ip:
            return first_ip
    try:
        return request.META.get("REMOTE_ADDR", "") or ""
    except Exception:
        return ""


def get_headers(request) -> dict:
    """Flatten request.headers into a plain dict[str, str]."""
    try:
        return dict(request.headers.items())
    except Exception:
        return {}


def get_query_params(request) -> dict:
    """Flatten request.GET into a plain dict[str, str].

    Only keeps the last value for a repeated key -- acceptable for
    parsing/logging purposes; anything needing all values per key
    should read request.GET directly.
    """
    try:
        return dict(request.GET.items())
    except Exception:
        return {}


def get_post_data(request) -> dict:
    """Flatten request.POST into a plain dict[str, str]. Same
    last-value-wins behavior as get_query_params."""
    try:
        return dict(request.POST.items())
    except Exception:
        return {}


def get_json_body(request) -> Optional[dict]:
    """Best-effort parse of a JSON request body.

    Returns None if the body isn't valid JSON, isn't a dict at the top
    level, or the request has no body -- never raises.
    """
    try:
        body = request.body
    except Exception:
        return None
    if not body:
        return None
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def get_cookies(request) -> dict:
    """Flatten request.COOKIES into a plain dict[str, str]."""
    try:
        return dict(request.COOKIES.items())
    except Exception:
        return {}


def get_uploaded_filenames(request) -> list:
    """List of filenames from any uploaded files (request.FILES),
    across all field names. Empty list if there are none."""
    try:
        return [f.name for _, files in request.FILES.lists() for f in files]
    except Exception:
        return []


def get_content_type(request) -> str:
    """The request's Content-Type header, or "" if absent."""
    try:
        return request.META.get("CONTENT_TYPE", "") or ""
    except Exception:
        return ""


def get_full_url(request) -> str:
    """Best-effort absolute URL reconstruction. Falls back to just the
    path if build_absolute_uri isn't available or fails (e.g. a bare
    fake/test request missing some environ keys)."""
    try:
        return request.build_absolute_uri()
    except Exception:
        return getattr(request, "path", "") or ""


def parse_request(request) -> ParsedRequest:
    """The main entry point: parse a request into a single
    ParsedRequest snapshot.

    Never raises -- any individual extraction that fails falls back to
    an empty value rather than propagating an exception, so callers
    (middleware, response builder, dashboard, benchmarking scripts)
    always get a usable object back, even for a malformed or
    adversarial request.
    """
    return ParsedRequest(
        ip=get_client_ip(request),
        method=getattr(request, "method", "") or "",
        path=getattr(request, "path", "") or "",
        full_url=get_full_url(request),
        query_params=get_query_params(request),
        post_data=get_post_data(request),
        json_body=get_json_body(request),
        cookies=get_cookies(request),
        headers=get_headers(request),
        files=get_uploaded_filenames(request),
        content_type=get_content_type(request),
    )
