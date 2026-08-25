"""NS-based parking detection (Layer 0): a domain delegated to a known parking
provider's nameservers is parked by definition, regardless of what it serves
over HTTP. This catches the DNS-only-parked domains the HTTP signature layers
miss (e.g. sedoparking-delegated brand-variant domains that don't return a
recognizable parking landing page, or don't answer HTTP at all)."""

from unittest.mock import MagicMock, patch


def test_matches_sedoparking_nameservers():
    from yads.modules.catchall_detector import CatchallDetectorScanner
    s = CatchallDetectorScanner(db_session=None)
    with patch.object(s, "_resolve_nameservers", return_value=["ns1.sedoparking.com.", "ns2.sedoparking.com."]):
        assert s._check_parking_ns("brandvariant.example") == "sedoparking.com"


def test_no_match_for_legitimate_nameservers():
    from yads.modules.catchall_detector import CatchallDetectorScanner
    s = CatchallDetectorScanner(db_session=None)
    with patch.object(s, "_resolve_nameservers", return_value=["ns1.musterbank.de.", "ns2.musterbank.de."]):
        assert s._check_parking_ns("musterbank.co.uk") is None


def test_no_match_when_no_nameservers():
    from yads.modules.catchall_detector import CatchallDetectorScanner
    s = CatchallDetectorScanner(db_session=None)
    with patch.object(s, "_resolve_nameservers", return_value=[]):
        assert s._check_parking_ns("nxdomain.example") is None


def test_run_scan_flags_parked_from_ns_without_http():
    """Layer 0 must short-circuit to parked before any HTTP fetch — so a
    DNS-parked host that never answers HTTP is still flagged."""
    from yads.modules.catchall_detector import CatchallDetectorScanner
    s = CatchallDetectorScanner(db_session=None)
    with patch.object(s, "_check_parking_ns", return_value="sedoparking.com"), \
         patch.object(s, "_fetch") as mock_fetch:
        result = s.run_scan("brandvariant.example", target_id=None)

    assert result["is_catch_all"] is True
    assert result["detection_method"] == "parking_ns"
    assert result["matched_signature"] == "ns:sedoparking.com"
    assert result["findings"] and result["findings"][0]["severity"] == "high"
    mock_fetch.assert_not_called()  # no HTTP needed when NS says parked
