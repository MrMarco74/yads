import unittest
from unittest.mock import MagicMock, patch
from yads.modules.crawler import Crawler

class TestCrawler(unittest.TestCase):
    def test_crawler_logic(self):
        print("\nTesting Crawler Logic...")
        mock_db = MagicMock()
        crawler = Crawler(db_session=mock_db)
        
        # Mock requests.get
        with patch('requests.get') as mock_get:
            def side_effect(url, **kwargs):
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.headers = {'Content-Type': 'text/html'}
                
                if url == "https://example.com":
                    # Homepage: Link to P2 and External
                    mock_resp.text = """
                        <html>
                            <title>Home</title>
                            <a href="/page2">Page 2</a>
                            <a href="https://google.com">Google</a>
                            <a href="https://facebook.com">Facebook</a>
                            <a href="https://google.com/search">Google Search</a>
                        </html>
                    """
                elif url == "https://example.com/page2":
                    # Page 2: Dead End (No internal links)
                    mock_resp.text = """
                        <html>
                            <title>Page 2</title>
                            <p>Content without links.</p>
                            <a href="https://twitter.com">Twitter</a>
                        </html>
                    """
                else:
                    mock_resp.status_code = 404
                
                return mock_resp

            mock_get.side_effect = side_effect

            result = crawler.run_scan("example.com")
            
            print(f"Stats: {result['stats']}")
            print(f"Dead Ends: {result['dead_ends']}")
            print(f"Collectors: {result['collectors']}")
            
            # Assertions
            self.assertEqual(result['stats']['pages_crawled'], 2, "Should crawl Home and Page 2")
            
            # Check Dead End
            dead_ends = [d['url'] for d in result['dead_ends']]
            self.assertIn("https://example.com/page2", dead_ends, "Page 2 should be a dead end")
            self.assertNotIn("https://example.com", dead_ends, "Home is not a dead end")
            
            # Check Collectors
            collectors = {c['domain']: c['count'] for c in result['collectors']}
            self.assertEqual(collectors.get('google.com'), 2, "Google should be found twice")
            self.assertEqual(collectors.get('facebook.com'), 1, "Facebook should be found once")

if __name__ == '__main__':
    unittest.main()
