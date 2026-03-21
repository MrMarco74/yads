import unittest
from unittest.mock import patch, MagicMock
from yads.worker_modules import validate_target_safety

class TestSSRFProtection(unittest.TestCase):

    @patch("yads.worker_modules.os.getenv")
    def test_allow_internal_scanning_bypass(self, mock_getenv):
        # When ALLOW_INTERNAL_SCANNING is true, everything should be allowed
        mock_getenv.return_value = "true"
        self.assertTrue(validate_target_safety("127.0.0.1"))
        self.assertTrue(validate_target_safety("192.168.1.1"))
        self.assertTrue(validate_target_safety("localhost"))

    @patch("yads.worker_modules.os.getenv")
    def test_block_private_ips(self, mock_getenv):
        mock_getenv.return_value = "false"
        self.assertFalse(validate_target_safety("127.0.0.1"))
        self.assertFalse(validate_target_safety("10.0.0.1"))
        self.assertFalse(validate_target_safety("192.168.1.50"))
        self.assertFalse(validate_target_safety("172.16.0.1"))
        self.assertFalse(validate_target_safety("169.254.169.254"))

    @patch("yads.worker_modules.os.getenv")
    @patch("socket.getaddrinfo")
    def test_block_resolving_to_private_ip(self, mock_getaddrinfo, mock_getenv):
        mock_getenv.return_value = "false"
        
        # Mock resolution of "internal.local" to a private IP
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("10.0.0.5", 0))
        ]
        self.assertFalse(validate_target_safety("internal.local"))

    @patch("yads.worker_modules.os.getenv")
    @patch("socket.getaddrinfo")
    def test_allow_public_ips(self, mock_getaddrinfo, mock_getenv):
        mock_getenv.return_value = "false"
        
        # 8.8.8.8 is public
        self.assertTrue(validate_target_safety("8.8.8.8"))
        
        # Mock resolution of "google.com" to a public IP
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("142.250.185.78", 0))
        ]
        self.assertTrue(validate_target_safety("google.com"))

    @patch("yads.worker_modules.os.getenv")
    @patch("socket.getaddrinfo")
    def test_fail_safe_on_error(self, mock_getaddrinfo, mock_getenv):
        mock_getenv.return_value = "false"
        mock_getaddrinfo.side_effect = Exception("DNS Failure")
        
        # Should return False (blocked) if validation fails due to error
        self.assertFalse(validate_target_safety("some-weird-domain.com"))

if __name__ == "__main__":
    unittest.main()
