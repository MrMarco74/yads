import dns.resolver

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
