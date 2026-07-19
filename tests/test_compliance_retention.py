import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone
from yads.worker_tasks import prune_old_scan_results

class TestDataRetention(unittest.TestCase):

    @patch("yads.worker_tasks.Session")
    @patch("yads.worker_tasks.engine")
    def test_prune_old_scan_results_calls_delete(self, mock_engine, mock_session):
        # Setup mock session
        session_instance = mock_session.return_value.__enter__.return_value

        # Execute the pruning task
        prune_old_scan_results()

        # Verify that session.execute was called multiple times (one for each table)
        # We expect 5 DELETE statements
        self.assertEqual(session_instance.execute.call_count, 5)

        # Verify that commit was called
        session_instance.commit.assert_called_once()

if __name__ == "__main__":
    unittest.main()
