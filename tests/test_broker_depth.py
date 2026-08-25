from unittest.mock import MagicMock, patch


def _conn_with_declare(depths_by_queue):
    channel = MagicMock()
    def _declare(q, passive=False):
        if q not in depths_by_queue:
            raise Exception("NOT_FOUND")
        res = MagicMock()
        res.message_count = depths_by_queue[q]
        return res
    channel.queue_declare.side_effect = _declare
    conn = MagicMock()
    conn.default_channel = channel
    conn.channel.return_value = channel
    conn.__enter__.return_value = conn
    conn.__exit__.return_value = False
    return conn


def test_returns_ready_counts_per_queue():
    conn = _conn_with_declare({"celery": 542, "discovery": 3})
    with patch("yads.core.broker_ops.Connection", return_value=conn):
        from yads.core.broker_ops import get_broker_queue_depth
        depths = get_broker_queue_depth("amqp://x//", queue_names=("celery", "discovery"))
    assert depths == {"celery": 542, "discovery": 3}


def test_missing_queue_reports_zero_not_error():
    conn = _conn_with_declare({"celery": 10})  # discovery missing
    with patch("yads.core.broker_ops.Connection", return_value=conn):
        from yads.core.broker_ops import get_broker_queue_depth
        depths = get_broker_queue_depth("amqp://x//", queue_names=("celery", "discovery"))
    assert depths == {"celery": 10, "discovery": 0}


def test_broker_unreachable_reports_all_zero():
    with patch("yads.core.broker_ops.Connection", side_effect=OSError("refused")):
        from yads.core.broker_ops import get_broker_queue_depth
        depths = get_broker_queue_depth("amqp://x//", queue_names=("celery",))
    assert depths == {"celery": 0}
