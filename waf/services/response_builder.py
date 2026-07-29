"""
response_builder.py

Builds the actual HTTP response returned to a client when the WAF
decides to block a request.

Input contract: a list of one or more "fired detector" dicts, each
matching Member 2's established detector output shape:
    {"attack": str, "score": float, "severity": str, "reason": str,
     "rule": str, "detector": str}

Why a list and not a single dict: a single malicious request can trip
multiple detectors at once (e.g. an SQLi payload that also matches an
XSS signature). This module aggregates all of them into one coherent
block decision rather than only reporting the first hit.

This module is intentionally decoupled from waf/engine.py and
decision_engine.py (Member 1's job) -- it doesn't decide WHETHER to
block, only HOW to render the block once that decision has been made.
If Member 1's actual decision payload shape differs once confirmed,
only build_block_decision()'s input handling should need to change --
build_response() and the JSON shape should remain stable.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

try:
    from django.http import HttpResponse
except ImportError:  # allows this module to be unit tested without a configured Django project
    HttpResponse = None


SEVERITY_ORDER = ["low", "medium", "high", "critical"]


@dataclass
class BlockDecision:
    blocked: bool
    severity: str
    score: float
    reasons: list = field(default_factory=list)
    attacks: list = field(default_factory=list)
    rules: list = field(default_factory=list)
    detectors: list = field(default_factory=list)
    request_id: str = ""
    timestamp: str = ""


def _severity_rank(severity: str) -> int:
    """Higher index = more severe. Unknown severities sort lowest so
    they never accidentally outrank a known one."""
    try:
        return SEVERITY_ORDER.index((severity or "").lower())
    except ValueError:
        return -1


def build_block_decision(detector_results: list, request_id: Optional[str] = None) -> BlockDecision:
    """Aggregate one or more fired-detector dicts into a single
    BlockDecision.

    - blocked is True whenever at least one result is passed in
      (an empty list means nothing fired -> not blocked).
    - severity is the highest severity among all fired detectors.
    - score is the max score among all fired detectors (not summed --
      a single high-confidence detector shouldn't be diluted or
      inflated by how many other detectors also happened to fire).
    - reasons/attacks/rules/detectors are deduplicated, order-preserving
      lists so the same message isn't repeated if multiple detectors
      report identical text.
    """
    results = detector_results or []

    if not results:
        return BlockDecision(
            blocked=False,
            severity="none",
            score=0.0,
            request_id=request_id or str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def _dedup(values: list) -> list:
        seen = set()
        out = []
        for v in values:
            if v and v not in seen:
                seen.add(v)
                out.append(v)
        return out

    best_severity = "low"
    best_rank = -1
    max_score = 0.0

    for r in results:
        sev = (r.get("severity") or "low")
        rank = _severity_rank(sev)
        if rank > best_rank:
            best_rank = rank
            best_severity = sev
        try:
            max_score = max(max_score, float(r.get("score", 0.0)))
        except (TypeError, ValueError):
            pass

    return BlockDecision(
        blocked=True,
        severity=best_severity,
        score=max_score,
        reasons=_dedup([r.get("reason", "") for r in results]),
        attacks=_dedup([r.get("attack", "") for r in results]),
        rules=_dedup([r.get("rule", "") for r in results]),
        detectors=_dedup([r.get("detector", "") for r in results]),
        request_id=request_id or str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def decision_to_dict(decision: BlockDecision) -> dict:
    """Plain-dict view of a BlockDecision, suitable for a JSON
    response body or for logging/dashboard consumption."""
    return {
        "blocked": decision.blocked,
        "severity": decision.severity,
        "score": decision.score,
        "reasons": decision.reasons,
        "attacks": decision.attacks,
        "rules": decision.rules,
        "detectors": decision.detectors,
        "request_id": decision.request_id,
        "timestamp": decision.timestamp,
    }


def build_response(decision: BlockDecision, status_code: int = 403):
    """Build the actual Django HttpResponse for a block decision.

    Body is JSON so the dashboard/API consumers and a human hitting it
    directly both get something readable. Never leaks internal rule
    names or raw signatures likely to help an attacker fine-tune a
    bypass -- only severity, a generic reason, and a request_id useful
    for support/log correlation.
    """
    if HttpResponse is None:
        raise RuntimeError("Django is not available in this environment; build_response() requires it.")

    body = {
        "error": "Request blocked",
        "message": "Your request was blocked by the Web Application Firewall.",
        "severity": decision.severity,
        "request_id": decision.request_id,
        "timestamp": decision.timestamp,
    }
    return HttpResponse(
        json.dumps(body),
        status=status_code,
        content_type="application/json",
    )


def build_block_response(detector_results: list, request_id: Optional[str] = None, status_code: int = 403):
    """Convenience one-shot: aggregate detector results straight into
    a final HttpResponse. What most callers (middleware, engine) will
    actually use."""
    decision = build_block_decision(detector_results, request_id=request_id)
    return build_response(decision, status_code=status_code)
