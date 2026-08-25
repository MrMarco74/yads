"""
When the queue is paused, /queue/control cancels the worker's broker consumer;
resume re-adds it. But reactivating QUEUE_ACTIVE by any other means (a raw DB
flag flip, an API restart) leaves the worker idle with no consumer. The
scheduler tick self-heals by re-asserting consumers on a false->true
transition. _should_reassert_consumers() is that decision.
"""


def test_reassert_on_pause_then_reactivate():
    from yads.core.scheduler import _should_reassert_consumers
    assert _should_reassert_consumers(prev_active=False, now_active=True) is True


def test_no_reassert_while_steady_active():
    from yads.core.scheduler import _should_reassert_consumers
    assert _should_reassert_consumers(prev_active=True, now_active=True) is False


def test_no_reassert_on_first_observation():
    """prev_active is None on the first tick — a freshly started worker already
    subscribed on startup, so no re-assert (and no false transition)."""
    from yads.core.scheduler import _should_reassert_consumers
    assert _should_reassert_consumers(prev_active=None, now_active=True) is False


def test_no_reassert_when_paused():
    from yads.core.scheduler import _should_reassert_consumers
    assert _should_reassert_consumers(prev_active=True, now_active=False) is False
