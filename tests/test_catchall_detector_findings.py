"""
Verifies catchall_detector.run_scan() always includes a "findings" key,
populated with one high-severity entry when is_catch_all is True and
empty otherwise. This is what scoring.py's generic-penalty mechanism
(Task 4) reads.
"""
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
