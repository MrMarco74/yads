import unittest
from unittest.mock import MagicMock, patch
from yads.modules.wayback_scanner import WaybackScanner
from yads.modules.infrastructure_scanner import InfrastructureScanner
import socket

class TestNewFeatures(unittest.TestCase):

    def test_wayback_scanner(self):
        print("\nTesting Wayback Scanner...")
        mock_db = MagicMock()
        scanner = WaybackScanner(mock_db)
        # Mock requests
        with patch('requests.get') as mock_get:
            # ... (rest is same)
            # Mock Availability API
            mock_resp_avail = MagicMock()
            mock_resp_avail.status_code = 200
            mock_resp_avail.json.return_value = {
                "archived_snapshots": {
                    "closest": {
                        "available": True,
                        "url": "http://web.archive.org/web/20230101/example.com",
                        "timestamp": "20230101"
                    }
                }
            }
            
            # Mock CDX API
            mock_resp_cdx = MagicMock()
            mock_resp_cdx.status_code = 200
            # CDX JSON format: list of lists. First row header.
            mock_resp_cdx.json.return_value = [
                ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"],
                ["com,example)/", "20100101000000", "http://example.com/", "text/html", "200", "abc", "123"]
            ]

            mock_get.side_effect = [mock_resp_avail, mock_resp_cdx]

            result = scanner.run_scan("example.com")
            print(f"Result: {result}")
            
            self.assertEqual(result['latest']['url'], "http://web.archive.org/web/20230101/example.com")
            self.assertIsNotNone(result['earliest'])
            self.assertEqual(result['earliest']['timestamp'], "20100101000000")

    def test_whois_extraction(self):
        print("\nTesting Whois Extraction...")
        mock_db = MagicMock()
        scanner = InfrastructureScanner(mock_db)
        
        # Mock socket to avoid real DNS
        with patch('socket.gethostbyname') as mock_socket:
            mock_socket.return_value = "1.2.3.4"
            
            # Mock IPWhois to avoid real network
            with patch('yads.modules.infrastructure_scanner.IPWhois') as MockIPWhois:
                instance = MockIPWhois.return_value
                instance.lookup_rdap.return_value = {"asn": "12345", "asn_description": "Test Cloud"}
                
                # Mock python-whois
                with patch('whois.whois') as mock_whois:
                    mock_w = MagicMock()
                    mock_w.registrar = "Test Registrar"
                    mock_w.creation_date = "2020-01-01"
                    mock_w.expiration_date = ["2025-01-01"] # List fmt
                    mock_w.emails = ["admin@example.com"]
                    mock_whois.return_value = mock_w
                    
                    # Run Scan
                    result = scanner.run_scan("example.com")
                    print(f"Whois Result: {result.get('whois')}")
                    
                    self.assertEqual(result['whois']['registrar'], "Test Registrar")
                    self.assertIn("admin@example.com", result['whois']['emails'])

if __name__ == '__main__':
    unittest.main()
