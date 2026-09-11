"""
Regression tests for POST /targets/import blocking the API event loop.

bulk_import_targets is an async handler, but used to run a blocking
socket.gethostbyname() (SSRF check) plus one synchronous duplicate-check
query per domain directly on the event loop. yads-api runs as a single
uvicorn process, so importing ~1300 domains froze every other request
(dashboard, notifications, health) for minutes and nginx answered 504.

These tests drive the handler directly with a fake request/session -- no
DB or network needed.
"""

import asyncio
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

from yads.api.routers import targets


class _FakeRequest:
    def __init__(self, form: dict):
        self._form = form

    async def form(self):
        return self._form


def _fake_session(existing_domains=()):
    session = MagicMock()
    session.exec.return_value.all.return_value = list(existing_domains)
    session.exec.return_value.first.return_value = None
    return session


def _slow_not_internal(delay: float):
    def _check(domain: str) -> bool:
        time.sleep(delay)
        return False
    return _check


async def _import(session, raw: str, verify_dns: bool = False):
    form = {"targets_raw": raw, "verify_dns": "true" if verify_dns else ""}
    return await targets.bulk_import_targets(
        request=_FakeRequest(form),
        session=session,
        user=SimpleNamespace(tenant_id=1),
        file_upload=None,
    )


async def test_import_does_not_block_event_loop(monkeypatch):
    monkeypatch.setattr(targets, "_is_internal_target", _slow_not_internal(0.05))
    raw = "\n".join(f"blocking-{i}.example.com" for i in range(20))

    ticks = 0
    stop = asyncio.Event()

    async def heartbeat():
        nonlocal ticks
        while not stop.is_set():
            ticks += 1
            await asyncio.sleep(0.01)

    hb = asyncio.create_task(heartbeat())
    await asyncio.sleep(0)
    await _import(_fake_session(), raw)
    stop.set()
    await hb

    # Serial on the loop: 20 x 50 ms of blocking = ~1 tick total.
    assert ticks >= 5, f"event loop starved during import (only {ticks} heartbeat ticks)"


async def test_import_screens_domains_concurrently(monkeypatch):
    monkeypatch.setattr(targets, "_is_internal_target", _slow_not_internal(0.1))
    raw = "\n".join(f"concurrent-{i}.example.com" for i in range(40))

    started = time.monotonic()
    await _import(_fake_session(), raw)
    elapsed = time.monotonic() - started

    # Serially this is 40 x 100 ms = 4 s.
    assert elapsed < 1.5, f"DNS screening ran serially ({elapsed:.2f}s)"


async def test_import_checks_duplicates_in_one_query(monkeypatch):
    monkeypatch.setattr(targets, "_is_internal_target", lambda d: False)
    session = _fake_session(existing_domains=["dup-1.example.com"])
    raw = "\n".join(f"dup-{i}.example.com" for i in range(50))

    response = await _import(session, raw)

    assert session.exec.call_count == 1
    added = [c.args[0].domain for c in session.add.call_args_list]
    assert len(added) == 49
    assert "dup-1.example.com" not in added
    assert "Imported+49+targets" in response.headers["location"]
    assert "1+skipped+duplicates" in response.headers["location"]
    session.commit.assert_called_once()


async def test_import_dedupes_after_cleaning(monkeypatch):
    monkeypatch.setattr(targets, "_is_internal_target", lambda d: False)
    session = _fake_session()

    await _import(session, "https://same.example.com/path\nsame.example.com\nSAME.example.com")

    added = [c.args[0].domain for c in session.add.call_args_list]
    assert added == ["same.example.com"]


async def test_import_skips_internal_and_dead_domains(monkeypatch):
    monkeypatch.setattr(targets, "_is_internal_target", lambda d: d.startswith("internal"))
    monkeypatch.setattr(targets, "_verify_domain_dns", lambda d: not d.startswith("dead"))
    session = _fake_session()

    response = await _import(
        session, "internal.example.com\ndead.example.com\nalive.example.com", verify_dns=True
    )

    added = [c.args[0].domain for c in session.add.call_args_list]
    assert added == ["alive.example.com"]
    assert "2+skipped+offline" in response.headers["location"]
