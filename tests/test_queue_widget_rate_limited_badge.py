# tests/test_queue_widget_rate_limited_badge.py
from unittest.mock import patch


def test_widget_context_includes_rate_limited_count():
    from yads.api.routers.queue import _widget_context

    mock_session = _make_mock_session()
    mock_request = object()
    mock_user = _make_mock_user()

    with patch("yads.api.routers.queue.get_rate_limited_module_count", return_value=3):
        ctx = _widget_context(mock_request, mock_session, mock_user, queue_active=True)

    assert ctx["rate_limited_count"] == 3


def _make_mock_session():
    from unittest.mock import MagicMock
    session = MagicMock()
    session.exec.return_value.one.return_value = 0
    return session


def _make_mock_user():
    from unittest.mock import MagicMock
    user = MagicMock()
    user.tenant_id = None
    return user
