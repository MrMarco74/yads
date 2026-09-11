"""
Wildcard-DNS artifact detection.

Parking providers/resellers (GoDaddy, Bodis/ParkingCrew, Sedo, ...) answer
*every* label under a parked zone. The old check probed ONE random label: a
single timeout left the wildcard IP set empty and every wordlist guess and
recursively re-discovered name was accepted, which grew ~5,500 bogus targets
under a single parked domain. These tests pin the replacement behaviour using
a fake resolver -- no network.
"""

import dns.resolver
import pytest

from yads.core import wildcard_dns
from yads.core.wildcard_dns import WildcardCache, find_wildcard_artifacts, probe_wildcard

PARK_IP = "64.190.63.222"


class _Answer(list):
    def __init__(self, ips, name, cname=None):
        super().__init__(ips)
        self.canonical_name = dns.name.from_text(cname or name)


class FakeResolver:
    """Resolves exact names from `records`; any other name under a zone in
    `wildcards` gets that zone's wildcard answer; everything else NXDOMAIN.
    `fail_first` makes the first N random-label lookups time out."""

    def __init__(self, records=None, wildcards=None, cnames=None, fail_all=(), fail_first=0):
        self.records = records or {}
        self.wildcards = wildcards or {}
        self.cnames = cnames or {}
        self.fail_all = set(fail_all)
        self.fail_first = fail_first
        self.calls = 0

    def resolve(self, name, rtype="A"):
        name = name.rstrip(".")
        self.calls += 1
        if name in self.records:
            return _Answer(self.records[name], name, self.cnames.get(name))
        for zone, ips in self.wildcards.items():
            if name.endswith("." + zone):
                if zone in self.fail_all:
                    raise dns.resolver.LifetimeTimeout()
                if self.fail_first > 0:
                    self.fail_first -= 1
                    raise dns.resolver.LifetimeTimeout()
                return _Answer(ips, name, self.cnames.get(zone))
        raise dns.resolver.NXDOMAIN()


def test_single_probe_timeout_still_detects_wildcard():
    resolver = FakeResolver(wildcards={"parked.test": [PARK_IP]}, fail_first=1)
    profile = probe_wildcard("parked.test", resolver)
    assert profile.status == "wildcard"
    assert PARK_IP in profile.ips


def test_all_probes_failing_is_unknown_not_none():
    resolver = FakeResolver(wildcards={"flaky.test": [PARK_IP]}, fail_all=["flaky.test"])
    assert probe_wildcard("flaky.test", resolver).status == "unknown"


def test_nxdomain_zone_has_no_wildcard():
    assert probe_wildcard("clean.test", FakeResolver()).status == "none"


def test_answer_matching_wildcard_ip_is_artifact_own_ip_is_not():
    resolver = FakeResolver(
        records={"www.parked.test": ["10.9.8.7"]},
        wildcards={"parked.test": [PARK_IP]},
    )
    cache = WildcardCache(resolver)
    assert cache.is_artifact("mailadmin.parked.test") is True
    assert cache.is_artifact("www.parked.test") is False


def test_matching_wildcard_cname_is_artifact_even_with_rotating_ips():
    resolver = FakeResolver(
        records={"shop.parked.test": ["198.51.100.99"]},
        wildcards={"parked.test": [PARK_IP]},
        cnames={"parked.test": "park.provider.test", "shop.parked.test": "park.provider.test"},
    )
    assert WildcardCache(resolver).is_artifact("shop.parked.test") is True


def test_nested_names_are_checked_against_their_immediate_parent_zone():
    resolver = FakeResolver(wildcards={"parked.test": [PARK_IP]})
    cache = WildcardCache(resolver)
    assert cache.is_artifact("secure.mobile.betplay.parked.test") is True


def test_names_without_wildcard_parent_are_never_artifacts():
    resolver = FakeResolver(records={"api.real.test": ["203.0.113.5"]})
    assert WildcardCache(resolver).is_artifact("api.real.test") is False


def test_parent_zone_is_probed_once_per_cache():
    resolver = FakeResolver(wildcards={"parked.test": [PARK_IP]})
    cache = WildcardCache(resolver)
    for i in range(10):
        cache.is_artifact(f"n{i}.parked.test")
    # 10 own lookups + one probe round for parked.test
    assert resolver.calls <= 10 + wildcard_dns.WILDCARD_PROBES


def test_scanner_drops_wildcard_answers_and_unverifiable_wordlist_guesses(monkeypatch):
    from yads.modules import dns_scanner

    resolver = FakeResolver(
        records={"www.parked.test": ["10.9.8.7"], "api.flaky.test": ["10.1.1.1"]},
        wildcards={"parked.test": [PARK_IP], "flaky.test": [PARK_IP]},
        fail_all=["flaky.test"],
    )
    monkeypatch.setattr(dns_scanner, "check_stop_signal", lambda db: None)
    scanner = dns_scanner.SubdomainScanner(db_session=None)
    candidates = {
        "www.parked.test": {"ct_log", "wordlist"},
        "mailadmin.parked.test": {"wordlist"},
        "resetpassword.parked.test": {"ct_log"},
        "api.flaky.test": {"ct_log"},
        "guess.flaky.test": {"wordlist"},
    }

    verified = scanner._verify_subdomains_parallel(
        candidates, WildcardCache(resolver), resolver, dns_scanner.logger
    )

    found = sorted(v["subdomain"] for v in verified)
    assert found == ["api.flaky.test", "www.parked.test"]


def test_find_wildcard_artifacts_skips_apexes_and_real_subdomains():
    resolver = FakeResolver(
        records={"parked.test": [PARK_IP], "www.parked.test": ["10.9.8.7"]},
        wildcards={"parked.test": [PARK_IP]},
    )
    domains = ["parked.test", "www.parked.test", "a.parked.test", "b.c.parked.test", "real.example"]

    artifacts = find_wildcard_artifacts(domains, WildcardCache(resolver), workers=4)

    assert sorted(artifacts) == ["a.parked.test", "b.c.parked.test"]
