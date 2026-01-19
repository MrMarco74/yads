
import sys
import os
import unittest
from unittest.mock import MagicMock, patch

# Ensure yads is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from yads.modules.api_discovery import ApiDiscoveryScanner

class TestApiDiscoveryScanner(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock()
        self.scanner = ApiDiscoveryScanner(db_session=self.mock_db)

    @patch('yads.modules.api_discovery.requests.get')
    def test_definitions_found_and_parsed(self, mock_get):
        # Setup mocks
        target = "example.com"
        
        # Mock side effects for requests.get
        def side_effect(url, **kwargs):
            mock_resp = MagicMock()
            mock_resp.status_code = 404
            
            # Connectivity check
            if url in ["https://example.com", "http://example.com"]:
                 mock_resp.status_code = 200
            
            # Swagger discovery
            if url == "https://example.com/swagger.json":
                mock_resp.status_code = 200
                mock_resp.headers = {"Content-Type": "application/json"}
                mock_resp.json.return_value = {
                    "swagger": "2.0",
                    "paths": {
                        "/users": {},
                        "/products": {}
                    }
                }
            
            return mock_resp

        mock_get.side_effect = side_effect

        # Run scan
        result = self.scanner.run_scan(target)
        
        # Assertions
        print("\n[Test Result] Data:", result)
        
        self.assertTrue(any(d['path'] == 'swagger.json' for d in result['definitions_found']))
        self.assertIn("/users", result['endpoints'])
        self.assertIn("/products", result['endpoints'])

    @patch('yads.modules.api_discovery.requests.get')
    def test_prefix_discovery(self, mock_get):
        target = "example.com"
        
        def side_effect(url, **kwargs):
            mock_resp = MagicMock()
            mock_resp.status_code = 404
            
            if url in ["https://example.com", "http://example.com"]:
                 mock_resp.status_code = 200
            
            # Prefix discovery
            if url == "https://example.com/api/v1":
                mock_resp.status_code = 200
            
            return mock_resp

        mock_get.side_effect = side_effect
        
        result = self.scanner.run_scan(target)
        print("\n[Test Result] Data:", result)
        
        self.assertTrue(any(p['path'] == 'api/v1' for p in result['prefixes_found']))

if __name__ == '__main__':
    unittest.main()
