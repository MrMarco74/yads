"""BaseScannerModule.process(precomputed=...) lets a caller that already ran
run_scan() (e.g. the parked-domain pre-check, which needs the live verdict for
its gating decision) hand that same observation to process() for persistence,
instead of process() running the scan a second time. This removes the
catchall_detector double-run (up to ~8 HTTP requests + 2 LLM calls per scan)
and the consistency gap where the two runs could disagree."""

import pytest

from yads.core.base import BaseScannerModule


class _DummyScanner(BaseScannerModule):
    ran = False

    @property
    def module_name(self) -> str:
        return "dummy_precomputed_test"

    def run_scan(self, target: str, target_id=None):
        type(self).ran = True
        return {"source": "run_scan", "findings": []}


@pytest.fixture
def a_target(db_session, test_tenant):
    from yads.models import Target
    from sqlmodel import select
    t = db_session.exec(
        select(Target).where(Target.domain == "precomputed-fixture.example.com")
    ).first()
    if not t:
        t = Target(domain="precomputed-fixture.example.com", tenant_id=test_tenant.id)
        db_session.add(t); db_session.commit(); db_session.refresh(t)
    return t


def test_process_with_precomputed_skips_run_scan(db_session, a_target):
    _DummyScanner.ran = False
    s = _DummyScanner(db_session=db_session)
    result = s.process(a_target.id, a_target.domain,
                       precomputed={"source": "precomputed", "findings": []})
    assert _DummyScanner.ran is False, "run_scan must not run when precomputed is given"
    assert result is not None
    assert result.data["source"] == "precomputed"


def test_process_without_precomputed_still_runs_scan(db_session, a_target):
    _DummyScanner.ran = False
    s = _DummyScanner(db_session=db_session)
    s.process(a_target.id, a_target.domain)
    assert _DummyScanner.ran is True
