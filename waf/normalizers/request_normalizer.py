"""
request_normalizer.py

Applies decoder.decode_fully() across an entire incoming request --
path, query params, POST body, headers, and cookies -- and returns a
single normalized structure that attack detectors (Member 2) and
logging (Member 3) can consume directly, instead of each of them
re-implementing decoding logic.

Duck-types against Django's HttpRequest (works with request.path,
request.GET, request.POST, request.COOKIES, request.headers,
request.method) so it doesn't hard-depend on Django being installed,
but slots straight into the middleware.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

from .decoder import decode_fully, FullDecodeResult, DEFAULT_MAX_ITERATIONS

# Headers/cookies where '+' should NOT be treated as a literal space
# during decode (form/query values use application/x-www-form-urlencoded
# semantics where '+' == space; most headers and cookies don't).
_PLUS_AS_SPACE_SOURCES = {"query", "body"}


@dataclass
class NormalizedField:
    source: str          # "query" | "body" | "header" | "cookie" | "path"
    key: str
    result: FullDecodeResult

    @property
    def value(self) -> str:
        return self.result.value

    @property
    def suspicious(self) -> bool:
        return self.result.suspicious


@dataclass
class NormalizedRequest:
    method: str
    raw_path: str
    path: FullDecodeResult
    fields: list[NormalizedField] = field(default_factory=list)

    def iter_fields(self) -> Iterator[NormalizedField]:
        yield from self.fields

    def suspicious_fields(self) -> list[NormalizedField]:
        return [f for f in self.fields if f.suspicious]

    def get(self, source: str, key: str) -> "NormalizedField | None":
        for f in self.fields:
            if f.source == source and f.key == key:
                return f
        return None

    def all_decoded_values(self) -> list[str]:
        """Flat list of every decoded value in the request -- the
        simplest possible input for a detector that just wants to
        regex-scan everything without caring where it came from."""
        return [f.value for f in self.fields]


def _normalize_mapping(
    mapping: Iterable[tuple[str, str]],
    source: str,
    max_iterations: int,
) -> list[NormalizedField]:
    plus_as_space = source in _PLUS_AS_SPACE_SOURCES
    fields: list[NormalizedField] = []
    for key, value in mapping:
        if value is None:
            continue
        result = decode_fully(str(value), max_iterations=max_iterations, plus_as_space=plus_as_space)
        fields.append(NormalizedField(source=source, key=key, result=result))
    return fields


def _items(obj: Any) -> Iterable[tuple[str, str]]:
    """Best-effort .items() extraction that works for dicts, Django
    QueryDict, and plain header dicts alike."""
    if obj is None:
        return []
    if hasattr(obj, "items"):
        return list(obj.items())
    return []


def normalize_request(request: Any, max_iterations: int = DEFAULT_MAX_ITERATIONS) -> NormalizedRequest:
    """Build a NormalizedRequest from a Django-style request object.

    Example (in middleware or a detector):
        normalized = normalize_request(request)
        for f in normalized.fields:
            for detector in detectors:
                result = detector.scan(f.value)
                if result:
                    ...
    """
    raw_path = getattr(request, "path", "") or ""
    path_result = decode_fully(raw_path, max_iterations=max_iterations, plus_as_space=False)

    fields: list[NormalizedField] = []
    fields += _normalize_mapping(_items(getattr(request, "GET", None)), "query", max_iterations)
    fields += _normalize_mapping(_items(getattr(request, "POST", None)), "body", max_iterations)
    fields += _normalize_mapping(_items(getattr(request, "COOKIES", None)), "cookie", max_iterations)
    fields += _normalize_mapping(_items(getattr(request, "headers", None)), "header", max_iterations)

    return NormalizedRequest(
        method=getattr(request, "method", ""),
        raw_path=raw_path,
        path=path_result,
        fields=fields,
    )


def normalize_value(value: str, max_iterations: int = DEFAULT_MAX_ITERATIONS, plus_as_space: bool = False) -> FullDecodeResult:
    """Convenience passthrough for normalizing a single ad-hoc string
    (e.g. a raw request body that isn't form-encoded, or a value a
    detector wants to re-check in isolation)."""
    return decode_fully(value, max_iterations=max_iterations, plus_as_space=plus_as_space)
