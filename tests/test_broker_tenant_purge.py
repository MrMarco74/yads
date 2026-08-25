from unittest.mock import MagicMock, patch


def _msg(args):
    """Build a fake kombu message whose decoded payload is Celery's
    [args, kwargs, embed] body. run_all_scans args are
    [target_id, domain, scan_types, tenant_id]."""
    m = MagicMock()
    m.payload = [args, {}, {}]
    m.delivery_tag = id(m)
    return m


def _make_channel(messages):
    """A channel whose basic_get yields the given messages once, then None."""
    channel = MagicMock()
    seq = list(messages) + [None]
    channel.basic_get.side_effect = seq
    return channel


def _patched_connection(channel):
    conn = MagicMock()
    conn.default_channel = channel
    conn.__enter__.return_value = conn
    conn.__exit__.return_value = False
    return conn


def test_drops_only_the_targeted_tenants_messages_and_keeps_the_rest():
    channel = _make_channel([
        _msg([1, "a.com", ["catchall_detector"], 2]),   # tenant 2 -> drop
        _msg([2, "b.com", ["dns_scanner"], 7]),          # tenant 7 -> keep
        _msg([3, "c.com", ["catchall_detector"], 2]),    # tenant 2 -> drop
    ])
    with patch("yads.core.broker_ops.Connection", return_value=_patched_connection(channel)):
        from yads.core.broker_ops import purge_broker_queue_for_tenant
        purged, undo = purge_broker_queue_for_tenant("amqp://x//", tenant_id=2)

    # tenant 2's two messages are acked (dropped); tenant 7's is requeued (kept)
    assert channel.basic_ack.call_count == 2
    assert channel.basic_reject.call_count == 1
    _, kwargs = channel.basic_reject.call_args
    assert kwargs.get("requeue") is True
    assert purged == 2


def test_returns_undo_records_for_dropped_tasks():
    channel = _make_channel([
        _msg([1, "a.com", ["catchall_detector"], 2]),
        _msg([9, "z.com", ["ssl_scanner"], 2]),
    ])
    with patch("yads.core.broker_ops.Connection", return_value=_patched_connection(channel)):
        from yads.core.broker_ops import purge_broker_queue_for_tenant
        purged, undo = purge_broker_queue_for_tenant("amqp://x//", tenant_id=2)

    assert purged == 2
    assert {u["target_id"] for u in undo} == {1, 9}
    assert undo[0]["scan_types"] == ["catchall_detector"]
    assert all(u["tenant_id"] == 2 for u in undo)


def test_undecodable_message_is_kept_not_dropped():
    """A message we cannot parse must be requeued (kept), never silently
    dropped — losing another tenant's scan would be worse than a stuck item."""
    bad = MagicMock()
    type(bad).payload = property(lambda self: (_ for _ in ()).throw(ValueError("bad")))
    bad.body = b"not-json"
    bad.delivery_tag = 1
    channel = _make_channel([bad])
    with patch("yads.core.broker_ops.Connection", return_value=_patched_connection(channel)):
        from yads.core.broker_ops import purge_broker_queue_for_tenant
        purged, undo = purge_broker_queue_for_tenant("amqp://x//", tenant_id=2)

    assert purged == 0
    channel.basic_ack.assert_not_called()
    channel.basic_reject.assert_called_once()
