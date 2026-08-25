from unittest.mock import MagicMock, patch


def test_purge_broker_queues_purges_each_named_queue_and_sums_counts():
    """purge_broker_queues must purge the actual broker queues via a channel
    (not a Redis list) and return the total messages removed across them."""
    mock_channel = MagicMock()
    # queue_purge returns the number of messages removed from that queue
    mock_channel.queue_purge.side_effect = [7, 3]

    mock_conn = MagicMock()
    mock_conn.default_channel = mock_channel
    # Connection is used as a context manager
    mock_conn.__enter__.return_value = mock_conn
    mock_conn.__exit__.return_value = False

    with patch("yads.core.broker_ops.Connection", return_value=mock_conn) as mock_connection:
        from yads.core.broker_ops import purge_broker_queues
        purged = purge_broker_queues("amqp://guest@localhost//", queue_names=("celery", "discovery"))

    mock_connection.assert_called_once_with("amqp://guest@localhost//")
    assert mock_channel.queue_purge.call_count == 2
    purged_queues = [c.args[0] for c in mock_channel.queue_purge.call_args_list]
    assert purged_queues == ["celery", "discovery"]
    assert purged == 10


def test_purge_broker_queues_survives_a_failing_queue_and_still_purges_others():
    """A failure purging one queue must not abort the others (best-effort)."""
    mock_channel = MagicMock()
    mock_channel.queue_purge.side_effect = [Exception("no such queue"), 5]

    mock_conn = MagicMock()
    mock_conn.default_channel = mock_channel
    mock_conn.__enter__.return_value = mock_conn
    mock_conn.__exit__.return_value = False

    with patch("yads.core.broker_ops.Connection", return_value=mock_conn):
        from yads.core.broker_ops import purge_broker_queues
        purged = purge_broker_queues("amqp://guest@localhost//", queue_names=("celery", "discovery"))

    assert mock_channel.queue_purge.call_count == 2
    assert purged == 5


def test_purge_broker_queues_returns_zero_when_broker_unreachable():
    """A broker connection failure must be swallowed and reported as 0 purged,
    never raised into the request handler that calls it."""
    with patch("yads.core.broker_ops.Connection", side_effect=OSError("connection refused")):
        from yads.core.broker_ops import purge_broker_queues
        purged = purge_broker_queues("amqp://guest@localhost//")

    assert purged == 0
