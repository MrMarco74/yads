import pytest
from unittest.mock import MagicMock, patch
from yads.worker_modules import _run_parallel_module
from yads.core.api_block_detection import ApiBlockedError


def test_run_parallel_module_reraises_api_blocked_error():
    mock_module_cls = MagicMock(__name__="MockModule")
    mock_instance = mock_module_cls.return_value
    mock_instance.process.side_effect = ApiBlockedError("test_service", retry_after=30)

    with patch("yads.worker_modules.validate_target_safety", return_value=True), \
         patch("yads.worker_modules.Session"):
        with pytest.raises(ApiBlockedError) as exc_info:
            _run_parallel_module(mock_module_cls, 1, "example.com")
        assert exc_info.value.service == "test_service"
        assert exc_info.value.retry_after == 30


def test_run_parallel_module_still_swallows_other_exceptions():
    mock_module_cls = MagicMock(__name__="MockModule")
    mock_instance = mock_module_cls.return_value
    mock_instance.process.side_effect = RuntimeError("boom")

    with patch("yads.worker_modules.validate_target_safety", return_value=True), \
         patch("yads.worker_modules.Session"):
        _run_parallel_module(mock_module_cls, 1, "example.com")  # must not raise
