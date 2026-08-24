"""
Verifies catchall_detector.run_scan() always includes a "findings" key,
populated with one high-severity entry when is_catch_all is True and
empty otherwise. This is what scoring.py's generic-penalty mechanism
(Task 4) reads.
"""
from unittest.mock import patch

import responses
from yads.modules.catchall_detector import CatchallDetectorScanner


@responses.activate
def test_findings_populated_when_parked_via_signature_match():
    responses.add(
        responses.GET, "http://example.com/",
        body="<html><title>example.com</title>This domain is for sale. Visit sedoparking.com</html>",
        status=200,
    )
    scanner = CatchallDetectorScanner(db_session=None)
    result = scanner.run_scan("example.com", target_id=None)
    assert result["is_catch_all"] is True
    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "high"
    assert "parked" in result["findings"][0]["title"].lower()


@responses.activate
def test_findings_empty_when_not_parked():
    responses.add(
        responses.GET, "http://example.com/",
        body="<html><title>Acme Corp</title>Welcome to our real business site.</html>",
        status=200,
    )
    scanner = CatchallDetectorScanner(db_session=None)
    result = scanner.run_scan("example.com", target_id=None)
    assert result["is_catch_all"] is False
    assert result["findings"] == []


def test_findings_empty_when_unreachable():
    scanner = CatchallDetectorScanner(db_session=None)
    # A domain that will fail to resolve/connect — matches the module's
    # existing unreachable-target handling.
    result = scanner.run_scan("this-domain-does-not-exist-abcxyz123.invalid", target_id=None)
    assert result["is_catch_all"] is None
    assert result["findings"] == []


@responses.activate
def test_llm_fallback_skipped_when_allow_llm_false():
    """
    Regression test for the unintended per-scan LLM billing change: a
    tenant who never selected catchall_detector must not trigger the LLM
    fallback layer even when layers 1/2 are inconclusive. run_scan() must
    not call _classify_with_llm at all when scanner.allow_llm is False.
    """
    responses.add(
        responses.GET, "http://example.com/",
        body="<html><title>Acme Corp</title>Welcome to our real business site with enough content to avoid the empty-body heuristic entirely.</html>",
        status=200,
    )
    scanner = CatchallDetectorScanner(db_session=None)
    scanner.allow_llm = False
    with patch.object(CatchallDetectorScanner, "_classify_with_llm") as mock_llm:
        result = scanner.run_scan("example.com", target_id=None)

    mock_llm.assert_not_called()
    assert result["llm_classification"] is None


@responses.activate
def test_llm_fallback_reachable_when_allow_llm_true_default():
    """
    allow_llm defaults to True and must preserve existing behavior: when
    layers 1/2 are inconclusive, _classify_with_llm is still invoked.
    """
    responses.add(
        responses.GET, "http://example.com/",
        body="<html><title>Acme Corp</title>Welcome to our real business site with enough content to avoid the empty-body heuristic entirely.</html>",
        status=200,
    )
    scanner = CatchallDetectorScanner(db_session=None)
    assert scanner.allow_llm is True  # default preserved
    with patch.object(
        CatchallDetectorScanner, "_classify_with_llm",
        return_value={"used": True, "verdict": "not_parked", "confidence": 0.9, "reasoning": "looks real", "reason": None},
    ) as mock_llm:
        result = scanner.run_scan("example.com", target_id=None)

    mock_llm.assert_called_once()
    assert result["llm_classification"]["used"] is True
