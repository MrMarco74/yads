import logging
import sys
import redis
import hashlib
from yads.modules.crawler import Crawler
from yads.config import settings

# Setup basic logging
logging.basicConfig(level=logging.DEBUG)

def verify_dedup():
    target = "https://example.com"
    r = redis.from_url(settings.REDIS_URL, decode_responses=True)
    
    # 1. Clear Redis state for target
    url_hash = hashlib.md5(target.encode()).hexdigest()
    key = f"crawler:visited:{url_hash}"
    r.delete(key)
    print(f"Cleared Redis key: {key}")

    crawler = Crawler()
    
    # 2. First Run (Should crawl)
    print("\n--- First Run ---")
    result1 = crawler.run_scan(target)
    pages1 = result1['stats']['pages_crawled']
    print(f"Pages crawled (1st run): {pages1}")
    
    if pages1 == 0:
        print("FAIL: First run did not crawl anything.")
        sys.exit(1)
        
    if not r.exists(key):
        print("FAIL: Redis key not set after first run.")
        sys.exit(1)
        
    # 3. Second Run (Should skip)
    print("\n--- Second Run ---")
    result2 = crawler.run_scan(target)
    nodes2 = len(result2['nodes'])
    print(f"Nodes fetched (2nd run): {nodes2}")
    
    if nodes2 > 0:
        print(f"FAIL: Second run fetched {nodes2} nodes. Deduplication failed.")
        sys.exit(1)
        
    print("\nSUCCESS: Deduplication works!")

if __name__ == "__main__":
    verify_dedup()
