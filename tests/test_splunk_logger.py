import unittest
from unittest.mock import patch, MagicMock
import time

from yads.core.splunk_logger import SplunkHECLogger


class TestSplunkHECLogger(unittest.TestCase):
    def setUp(self):
        self.logger = SplunkHECLogger()
        self.logger.token = "test-token"
        self.logger.url = "http://localhost:8088/services/collector/event"
        self.logger.enabled = True

    def test_get_stats(self):
        stats = self.logger.get_stats()
        self.assertIn("enabled", stats)
        self.assertIn("queue_depth", stats)
        self.assertIn("sent_count", stats)

    @patch("requests.post")
    def test_send_payload_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        payload = {"event": {"test": "data"}}
        initial_sent = self.logger.sent_count
        self.logger._send_payload(payload)
        
        self.assertEqual(self.logger.sent_count, initial_sent + 1)

    @patch("requests.post")
    def test_test_connection(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        success, msg = self.logger.test_connection("http://localhost:8088", "token")
        self.assertTrue(success)
        self.assertIn("Successfully connected", msg)


if __name__ == "__main__":
    unittest.main()
