"""The RDAP lookup must not sit in ipwhois' default rate-limit backoff.

ipwhois.lookup_rdap defaults to retry_count=3 and rate_limit_timeout=120, so a
single 429 from an RIR parks a worker slot for up to ~6 minutes. During bulk
scans every slot ended up waiting there, draining the queue at ~25 targets/h.
"""
from unittest.mock import patch

from yads.modules.infrastructure_scanner import InfrastructureScanner


def _rdap_kwargs():
    scanner = InfrastructureScanner(db_session=None)
    with patch("yads.modules.infrastructure_scanner.IPWhois") as ipwhois_cls:
        ipwhois_cls.return_value.lookup_rdap.return_value = {"asn": "3320"}
        scanner._lookup_asn_and_cloud("192.0.2.1")
    return ipwhois_cls.return_value.lookup_rdap.call_args.kwargs


def test_rdap_rate_limit_backoff_is_short():
    assert _rdap_kwargs().get("rate_limit_timeout", 120) <= 10


def test_rdap_retries_at_most_once():
    assert _rdap_kwargs().get("retry_count", 3) <= 1
