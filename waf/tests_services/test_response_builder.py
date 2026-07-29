"""
Unit tests for services.response_builder

Run with: pytest waf/tests_services/test_response_builder.py -v
"""

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from waf.services.response_builder import (
    build_block_decision,
    decision_to_dict,
    build_response,
    build_block_response,
    BlockDecision,
)


SQLI_RESULT = {
    "attack": "sqli",
    "score": 8.5,
    "severity": "high",
    "reason": "SQL injection pattern matched in query param",
    "rule": "sqli-001",
    "detector": "sqli_detector",
}

XSS_RESULT = {
    "attack": "xss",
    "score": 6.0,
    "severity": "medium",
    "reason": "script tag detected in POST body",
    "rule": "xss-004",
    "detector": "xss_detector",
}

CRITICAL_RESULT = {
    "attack": "command_injection",
    "score": 9.9,
    "severity": "critical",
    "reason": "shell metacharacters detected",
    "rule": "cmdi-002",
    "detector": "command_injection_detector",
}


def test_empty_results_means_not_blocked():
    decision = build_block_decision([])
    assert decision.blocked is False
    assert decision.severity == "none"
    assert decision.score == 0.0


def test_none_results_means_not_blocked():
    decision = build_block_decision(None)
    assert decision.blocked is False


def test_single_result_blocked():
    decision = build_block_decision([SQLI_RESULT])
    assert decision.blocked is True
    assert decision.severity == "high"
    assert decision.score == 8.5
    assert decision.attacks == ["sqli"]
    assert decision.rules == ["sqli-001"]
    assert decision.detectors == ["sqli_detector"]


def test_multiple_results_take_highest_severity():
    decision = build_block_decision([SQLI_RESULT, XSS_RESULT])
    # high > medium
    assert decision.severity == "high"


def test_multiple_results_critical_wins_over_high():
    decision = build_block_decision([SQLI_RESULT, CRITICAL_RESULT, XSS_RESULT])
    assert decision.severity == "critical"


def test_score_is_max_not_sum():
    decision = build_block_decision([SQLI_RESULT, XSS_RESULT])
    assert decision.score == 8.5  # max(8.5, 6.0), not 14.5


def test_reasons_deduplicated():
    duplicate = dict(SQLI_RESULT)
    decision = build_block_decision([SQLI_RESULT, duplicate])
    assert decision.reasons == [SQLI_RESULT["reason"]]


def test_attacks_rules_detectors_all_collected():
    decision = build_block_decision([SQLI_RESULT, XSS_RESULT])
    assert set(decision.attacks) == {"sqli", "xss"}
    assert set(decision.rules) == {"sqli-001", "xss-004"}
    assert set(decision.detectors) == {"sqli_detector", "xss_detector"}


def test_unknown_severity_does_not_outrank_known():
    weird = dict(SQLI_RESULT, severity="banana")
    decision = build_block_decision([weird, XSS_RESULT])
    # "banana" ranks -1 (unknown), so medium (xss) should win
    assert decision.severity == "medium"


def test_missing_score_defaults_gracefully():
    incomplete = {"attack": "xss", "severity": "low", "reason": "x", "rule": "r", "detector": "d"}
    decision = build_block_decision([incomplete])
    assert decision.score == 0.0


def test_request_id_generated_when_not_provided():
    decision = build_block_decision([SQLI_RESULT])
    assert decision.request_id != ""


def test_request_id_passed_through_when_provided():
    decision = build_block_decision([SQLI_RESULT], request_id="req-123")
    assert decision.request_id == "req-123"


def test_timestamp_is_set():
    decision = build_block_decision([SQLI_RESULT])
    assert decision.timestamp != ""


def test_decision_to_dict_shape():
    decision = build_block_decision([SQLI_RESULT])
    d = decision_to_dict(decision)
    assert d["blocked"] is True
    assert d["severity"] == "high"
    assert d["score"] == 8.5
    assert "reasons" in d and "attacks" in d and "rules" in d and "detectors" in d
    assert d["request_id"] == decision.request_id


def test_decision_to_dict_is_json_serializable():
    decision = build_block_decision([SQLI_RESULT, XSS_RESULT])
    d = decision_to_dict(decision)
    # should not raise
    json.dumps(d)


def test_build_response_raises_without_django(monkeypatch):
    import waf.services.response_builder as rb
    monkeypatch.setattr(rb, "HttpResponse", None)
    decision = build_block_decision([SQLI_RESULT])
    with pytest.raises(RuntimeError):
        build_response(decision)


def test_build_block_response_end_to_end_if_django_available():
    try:
        import django  # noqa: F401
    except ImportError:
        pytest.skip("Django not installed/configured in this environment")

    response = build_block_response([SQLI_RESULT], request_id="req-456")
    assert response.status_code == 403
    body = json.loads(response.content)
    assert body["request_id"] == "req-456"
    assert body["severity"] == "high"


def test_build_block_response_custom_status_code():
    try:
        import django  # noqa: F401
    except ImportError:
        pytest.skip("Django not installed/configured in this environment")

    response = build_block_response([CRITICAL_RESULT], status_code=429)
    assert response.status_code == 429
