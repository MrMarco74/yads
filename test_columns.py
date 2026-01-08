import sys
import os
import logging
sys.path.insert(0, os.getcwd())

from yads.modules.web_analyzer import WebAnalyzer
from yads.modules.dns_scanner import DNSScanner

# Config logging to see info
logging.basicConfig(level=logging.INFO)

def test_web():
    print("Testing WebAnalyzer on example.com...")
    scanner = WebAnalyzer()
    res = scanner.run_scan("example.com")
    print(f"HTTP Status: {res.get('http_status')}")
    print(f"HTTPS Status: {res.get('https_status')}")
    print(f"Redirect: {res.get('https_redirect')}")

    print("\nTesting DNSScanner on example.com...")
    scanner = DNSScanner(None)
    res = scanner.run_scan("example.com")
    print(f"Wildcard Detected: {res.get('wildcard_detected')}")

if __name__ == "__main__":
    test_web()
    test_dns()
