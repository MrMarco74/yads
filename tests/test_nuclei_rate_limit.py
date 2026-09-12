"""Nuclei must run with an explicit request-rate limit.

Without -rl nuclei uses its default of 150 requests/s. Every request leaves a
conntrack entry behind that lingers for a minute or two after the connection
closes, so the table fills to roughly rate x lifetime -- ~6,900 entries were
measured against a single target on 2026-09-12, which is what exhausts a
home router's NAT table. The rate is the lever, not the thread count.

It is also simply the politer way to scan someone else's domain.
"""
from unittest.mock import MagicMock

import pytest

from yads.modules.nuclei_scanner import NucleiScanner, NUCLEI_RATE_LIMIT_DEFAULT


def _scanner(config_value=None):
    """Scanner whose DB returns *config_value* for NUCLEI_RATE_LIMIT."""
    db = MagicMock()
    db.get.return_value = MagicMock(value=config_value) if config_value is not None else None
    return NucleiScanner(db_session=db)


def test_rate_limit_is_applied_by_default():
    cmd = _scanner()._build_command("https://example.com")
    assert "-rl" in cmd
    assert cmd[cmd.index("-rl") + 1] == str(NUCLEI_RATE_LIMIT_DEFAULT)


def test_default_is_conservative_enough_for_a_home_line():
    """At ~60s conntrack lifetime the default must stay well under a
    consumer router's table: 150/s (nuclei's own default) does not."""
    assert 0 < NUCLEI_RATE_LIMIT_DEFAULT <= 25


def test_configured_value_wins():
    cmd = _scanner("50")._build_command("https://example.com")
    assert cmd[cmd.index("-rl") + 1] == "50"


def test_zero_disables_the_limit():
    """An explicit 0 means "use nuclei's own default" -- for anyone scanning
    from a line that can take it. It must drop the flag, not pass -rl 0
    (which nuclei reads as unlimited-but-set and is easy to misread)."""
    cmd = _scanner("0")._build_command("https://example.com")
    assert "-rl" not in cmd


def test_malformed_value_falls_back_to_the_default():
    """A typo in the setting must not silently unleash 150 req/s."""
    cmd = _scanner("schnell")._build_command("https://example.com")
    assert cmd[cmd.index("-rl") + 1] == str(NUCLEI_RATE_LIMIT_DEFAULT)


def test_negative_value_falls_back_to_the_default():
    cmd = _scanner("-5")._build_command("https://example.com")
    assert cmd[cmd.index("-rl") + 1] == str(NUCLEI_RATE_LIMIT_DEFAULT)


def test_base_command_is_unchanged():
    cmd = _scanner()._build_command("https://example.com")
    assert cmd[0] == "nuclei"
    for flag in ("-u", "-j", "-silent", "-nc"):
        assert flag in cmd
    assert cmd[cmd.index("-u") + 1] == "https://example.com"


def test_works_without_a_db_session():
    """Modules are also run ad hoc without a session; that must not crash."""
    cmd = NucleiScanner(db_session=None)._build_command("https://example.com")
    assert cmd[cmd.index("-rl") + 1] == str(NUCLEI_RATE_LIMIT_DEFAULT)
