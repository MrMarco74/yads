"""
Guards against public-API scanner modules regressing back to raw
`requests.get/post/head` calls that bypass circuit-breaker detection.
Each entry: (file relative to yads/, forbidden raw-requests call count expected == 0).
"""
import re
from pathlib import Path

import pytest

YADS_ROOT = Path(__file__).resolve().parents[1] / "yads"

MIGRATED_FILES = [
    "modules/crtSH_client.py",
    "modules/ct_monitor.py",
    "modules/dns_history_scanner.py",
    "modules/asn_scanner.py",
    "modules/ipv6_scanner.py",
    "modules/rpki_scanner.py",
    "modules/phishing_scanner.py",
    "modules/tls_deep_scanner.py",
]

# dns_scanner.py has both migrated (_fetch_hackertarget) and non-HTTP code;
# checked separately by function name below instead of whole-file.
# infrastructure_scanner.py mixes one migrated third-party-API call
# (_lookup_geoip_enhanced, ipinfo.io) with one intentionally-unmigrated
# call (_check_bucket_status, S3 probe against the *scanned target's*
# infrastructure, not a shared third-party API) — checked separately below.
# wayback_scanner.py mixes one migrated third-party-API call (_query_cdx,
# web.archive.org CDX API) with one intentionally-unmigrated call
# (_is_still_live, a HEAD probe against the *discovered URL*, not the
# wayback API) — checked separately below.
# dependency_confusion.py mixes one migrated call (_check_npm_exists, npm
# registry) with one intentionally-unmigrated call (_fetch, arbitrary
# target-hosted manifest fetch) — checked separately below.
# mobile_app_discovery.py mixes one migrated call (_search_itunes, iTunes
# search API) with one intentionally-unmigrated call (_get, arbitrary
# discovered app-store/company URL) — checked separately below.
RAW_REQUESTS_CALL = re.compile(r"\brequests\.(get|post|head)\(")


@pytest.mark.parametrize("relpath", MIGRATED_FILES)
def test_module_has_no_raw_requests_calls(relpath):
    src = (YADS_ROOT / relpath).read_text()
    matches = RAW_REQUESTS_CALL.findall(src)
    assert matches == [], f"{relpath} still has raw requests.* calls: {matches} — use throttled_get/throttled_post/throttled_head with a service= kwarg"


def test_dns_scanner_fetch_hackertarget_is_migrated():
    src = (YADS_ROOT / "modules/dns_scanner.py").read_text()
    start = src.index("def _fetch_hackertarget")
    end = src.index("\n    def ", start + 1)
    body = src[start:end]
    assert "requests.get(" not in body
    assert "throttled_get(" in body


def test_infrastructure_scanner_ipinfo_call_is_migrated():
    src = (YADS_ROOT / "modules/infrastructure_scanner.py").read_text()
    start = src.index("def _lookup_geoip_enhanced")
    end = src.index("\n    def ", start + 1)
    body = src[start:end]
    assert "requests.get(" not in body
    assert "throttled_get(" in body


def test_wayback_scanner_query_cdx_is_migrated():
    src = (YADS_ROOT / "modules/wayback_scanner.py").read_text()
    start = src.index("def _query_cdx")
    # _query_cdx is the last method in the class, so there's no further
    # "\n    def " boundary to search for.
    body = src[start:]
    assert "requests.get(" not in body
    assert "throttled_get(" in body


def test_wayback_scanner_is_still_live_stays_unmigrated():
    src = (YADS_ROOT / "modules/wayback_scanner.py").read_text()
    start = src.index("def _is_still_live")
    end = src.index("\n    def ", start + 1)
    body = src[start:end]
    assert "requests.head(" in body


def test_dependency_confusion_npm_check_is_migrated():
    src = (YADS_ROOT / "modules/dependency_confusion.py").read_text()
    start = src.index("def _check_npm_exists")
    end = src.index("\ndef ", start + 1)
    body = src[start:end]
    assert "requests.get(" not in body
    assert "throttled_get(" in body


def test_mobile_app_discovery_itunes_search_is_migrated():
    src = (YADS_ROOT / "modules/mobile_app_discovery.py").read_text()
    start = src.index("def _search_itunes")
    end = src.index("\ndef ", start + 1)
    body = src[start:end]
    assert "requests.get(" not in body
    assert "throttled_get(" in body
