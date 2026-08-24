"""
Verifies the target-list export (both the dict-based Excel/PDF path via
_get_targets_data and the CSV route's inline column building) include a
Tags column sourced from Target.tags.
"""
from unittest.mock import MagicMock
from datetime import datetime


def _mock_target(id=1, domain="example.com", tags=None):
    t = MagicMock()
    t.id = id
    t.domain = domain
    t.created_at = datetime(2026, 1, 1, 12, 0, 0)
    t.scan_status = "idle"
    t.tags = tags or []
    return t


def test_get_targets_data_includes_tags_column():
    from yads.api.routers.reports import _get_targets_data

    mock_session = MagicMock()
    mock_session.exec.return_value.all.return_value = [_mock_target(tags=["sedoparking", "customer-a"])]
    mock_session.exec.return_value.first.return_value = None  # no ScanResult -> "Never"
    mock_user = MagicMock(tenant_id=None, role="admin")

    data = _get_targets_data(mock_session, mock_user, for_export=True)

    assert len(data) == 1
    assert data[0]["Tags"] == "sedoparking, customer-a"


def test_get_targets_data_empty_tags_renders_empty_string():
    from yads.api.routers.reports import _get_targets_data

    mock_session = MagicMock()
    mock_session.exec.return_value.all.return_value = [_mock_target(tags=[])]
    mock_session.exec.return_value.first.return_value = None
    mock_user = MagicMock(tenant_id=None, role="admin")

    data = _get_targets_data(mock_session, mock_user, for_export=True)

    assert data[0]["Tags"] == ""
