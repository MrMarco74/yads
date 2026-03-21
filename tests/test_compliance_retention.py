import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone
from yads.worker_tasks import prune_old_scan_results, _trigger_support_portal_cleanup

class TestDataRetention(unittest.TestCase):

    @patch("yads.worker_tasks.Session")
    @patch("yads.worker_tasks.engine")
    @patch("yads.worker_tasks._trigger_support_portal_cleanup")
    def test_prune_old_scan_results_calls_delete(self, mock_cleanup, mock_engine, mock_session):
        # Setup mock session
        session_instance = mock_session.return_value.__enter__.return_value
        
        # Execute the pruning task
        prune_old_scan_results()
        
        # Verify that session.execute was called multiple times (one for each table)
        # We expect 5 DELETE statements
        self.assertEqual(session_instance.execute.call_count, 5)
        
        # Verify that commit was called
        session_instance.commit.assert_called_once()
        
        # Verify that Support Portal cleanup was triggered
        mock_cleanup.assert_called_once()

    @patch("yads.worker_tasks.requests.post")
    @patch("yads.worker_tasks.os.getenv")
    @patch("yads.worker_tasks.settings")
    def test_trigger_support_portal_cleanup_success(self, mock_settings, mock_getenv, mock_post):
        # Setup mocks
        mock_settings.SUPPORT_PORTAL_URL = "http://support.test"
        mock_getenv.return_value = "test-token"
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        # Execute
        _trigger_support_portal_cleanup()
        
        # Verify request
        mock_post.assert_called_once_with(
            "http://support.test/api/admin/cleanup",
            headers={"Authorization": "Bearer test-token"},
            timeout=10
        )

    @patch("yads.worker_tasks.requests.post")
    @patch("yads.worker_tasks.os.environ.get")
    def test_trigger_support_portal_cleanup_missing_config(self, mock_getenv, mock_post):
        # Setup mock to return None for config
        mock_getenv.return_value = None
        
        # Execute
        _trigger_support_portal_cleanup()
        
        # Should NOT make a post request
        mock_post.assert_not_called()

if __name__ == "__main__":
    unittest.main()
