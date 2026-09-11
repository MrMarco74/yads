from pathlib import Path

import dns.resolver
import pytest

from yads.core.dns_resolver import DNS_SERVER_ENV, make_resolver


def test_env_server_is_used(monkeypatch):
    monkeypatch.setenv(DNS_SERVER_ENV, "172.31.53.53")
    assert make_resolver().nameservers == ["172.31.53.53"]


def test_env_accepts_comma_separated_list(monkeypatch):
    monkeypatch.setenv(DNS_SERVER_ENV, " 172.31.53.53, 172.31.53.54 ,")
    assert make_resolver().nameservers == ["172.31.53.53", "172.31.53.54"]


def test_unset_env_keeps_system_resolver(monkeypatch):
    monkeypatch.delenv(DNS_SERVER_ENV, raising=False)
    assert make_resolver().nameservers == dns.resolver.Resolver().nameservers


def test_explicit_nameservers_win_over_env(monkeypatch):
    monkeypatch.setenv(DNS_SERVER_ENV, "172.31.53.53")
    assert make_resolver(nameservers=["192.0.2.1"]).nameservers == ["192.0.2.1"]


def test_empty_explicit_list_falls_back_to_env(monkeypatch):
    # Callers pass custom_ns=[] meaning "no custom servers configured".
    monkeypatch.setenv(DNS_SERVER_ENV, "172.31.53.53")
    assert make_resolver(nameservers=[]).nameservers == ["172.31.53.53"]


def test_timeouts_are_applied(monkeypatch):
    monkeypatch.delenv(DNS_SERVER_ENV, raising=False)
    r = make_resolver(timeout=1.0, lifetime=3.0)
    assert (r.timeout, r.lifetime) == (1.0, 3.0)


def test_defaults_match_dnspython(monkeypatch):
    monkeypatch.delenv(DNS_SERVER_ENV, raising=False)
    r = make_resolver()
    assert (r.timeout, r.lifetime) == (2.0, 5.0)


def test_env_empty_string_raises(monkeypatch):
    # Env var set to empty string should raise, not silently fall back
    monkeypatch.setenv(DNS_SERVER_ENV, "")
    with pytest.raises(ValueError, match="YADS_DNS_SERVER is set but contains no nameserver"):
        make_resolver()


def test_env_whitespace_only_raises(monkeypatch):
    # Env var set to whitespace/commas only should raise
    monkeypatch.setenv(DNS_SERVER_ENV, " , ")
    with pytest.raises(ValueError, match="YADS_DNS_SERVER is set but contains no nameserver"):
        make_resolver()


def test_explicit_nameservers_ignore_empty_env(monkeypatch):
    # Explicit nameservers should work even if env is set but empty
    monkeypatch.setenv(DNS_SERVER_ENV, "")
    assert make_resolver(nameservers=["192.0.2.1"]).nameservers == ["192.0.2.1"]


def test_no_direct_resolver_construction_outside_factory():
    pkg = Path(__file__).resolve().parents[1] / "yads"
    factory = pkg / "core" / "dns_resolver.py"
    offenders = [
        f"{path.relative_to(pkg)}:{lineno}"
        for path in pkg.rglob("*.py")
        if path != factory
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if "dns.resolver.Resolver(" in line
    ]
    assert offenders == [], f"use yads.core.dns_resolver.make_resolver: {offenders}"
