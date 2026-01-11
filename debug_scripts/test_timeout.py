import unittest
from unittest.mock import patch, MagicMock
import os
import sys

# Ensure yads is importable
sys.path.append('/app')

# Set ENV before importing config to verify it picks it up
os.environ["YADS_WEB_TIMEOUT"] = "2"

from yads.config import settings
from yads.modules.web_analyzer import WebAnalyzer

class TestWebTimeout(unittest.TestCase):
    def test_01_timeout_setting_loaded(self):
        print(f"\n[Test] Loaded WEB_REQUEST_TIMEOUT: {settings.WEB_REQUEST_TIMEOUT}")
        self.assertEqual(settings.WEB_REQUEST_TIMEOUT, 2, "Settings did not load env var correctly")

    @patch('requests.get')
    def test_02_requests_uses_timeout(self, mock_get):
        print("\n[Test] Verifying requests.get is called with correct timeout...")
        
        # Setup Mock
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.history = []
        mock_resp.url = "https://example.com"
        mock_get.return_value = mock_resp
        
        # Init Analyzer
        analyzer = WebAnalyzer()
        
        # Run - this will call both http and https check
        # We mock specific return so it doesn't try playwright if we control the flow
        # If we return success for HTTPS, it might proceed to playwright.
        # Let's mock _run_headless to avoid needing to mock playwright
        with patch.object(analyzer, '_run_headless') as mock_headless:
            analyzer.run_scan("example.com")
        
        # Verify requests.get calls
        # Expect at least one call
        self.assertTrue(mock_get.called)
        
        # Check the arguments of the calls
        for call in mock_get.call_args_list:
            args, kwargs = call
            timeout_used = kwargs.get('timeout')
            print(f" -> requests.get called with timeout={timeout_used}")
            self.assertEqual(timeout_used, 2, "requests.get not using configured timeout")

    @patch('requests.get')
    def test_02b_db_override_uses_timeout(self, mock_get):
        print("\n[Test] Verifying DB override works...")
        
        # Setup Mock DB Session
        mock_session = MagicMock()
        mock_conf = MagicMock()
        mock_conf.value = "5"
        mock_session.get.return_value = mock_conf
        
        # Setup Mock Response
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp
        
        # Init Analyzer with DB Session
        analyzer = WebAnalyzer(db_session=mock_session)
        
        with patch.object(analyzer, '_run_headless') as mock_headless:
            analyzer.run_scan("example.com")
            
        # Check timeout used
        # Should be 5 (from DB) not 2 (from Env)
        for call in mock_get.call_args_list:
            args, kwargs = call
            timeout_used = kwargs.get('timeout')
            print(f" -> requests.get called with timeout={timeout_used}")
            self.assertEqual(timeout_used, 5, "requests.get did not use DB override")

    @patch('yads.modules.web_analyzer.sync_playwright')
    def test_03_playwright_uses_timeout(self, mock_playwright):
        print("\n[Test] Verifying playwright page.goto is called with correct timeout...")
        
        # Setup complex mock for context manager
        mock_p = MagicMock()
        mock_browser = MagicMock()
        mock_context = MagicMock()
        mock_page = MagicMock()
        
        mock_playwright.return_value.__enter__.return_value = mock_p
        mock_p.chromium.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context
        mock_context.new_page.return_value = mock_page
        
        # Mock actual scan results to trigger headless
        # We can call _run_headless directly to test it in isolation
        analyzer = WebAnalyzer()
        results = {"visuals": {}, "keywords_found": [], "meta_tags": {}, "tech_stack": [], "redirect_chain": []}
        
        # We must pass the timeout explicitly as run_scan does
        analyzer._run_headless("https://example.com", results, timeout=settings.WEB_REQUEST_TIMEOUT)
        
        # Verify page.goto
        self.assertTrue(mock_page.goto.called)
        args, kwargs = mock_page.goto.call_args
        
        # Playwright uses milliseconds, so expect 2 * 1000 = 2000
        timeout_used = kwargs.get('timeout')
        print(f" -> page.goto called with timeout={timeout_used}")
        self.assertEqual(timeout_used, 2000, "page.goto not using configured timeout (in ms)")

if __name__ == '__main__':
    unittest.main()
