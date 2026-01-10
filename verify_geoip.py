import logging
import sys
# Configure logging
logging.basicConfig(level=logging.INFO)

from yads.modules.infrastructure_scanner import InfrastructureScanner

# Mocking DB session as it might be needed for fallback logic but not primary Ip lookup
class MockDB:
    def exec(self, query):
        return None

def test_scan():
    scanner = InfrastructureScanner(db_session=MockDB())
    domain = "example-client.de"
    
    print(f"Scanning {domain}...")
    result = scanner.run_scan(domain)
    
    print("\nScan Result Keys:", result.keys())
    
    if "geoip" in result:
        print("\nSUCCESS: GeoIP found!")
        print(result["geoip"])
        
        if result["geoip"].get("country_name"):
            print("Country Name OK")
        else:
            print("FAIL: Country Name missing")
    else:
        print("\nFAIL: GeoIP NOT found")
        
    if result.get("cloud_provider"):
        print(f"Cloud Provider Detected: {result['cloud_provider']}")

if __name__ == "__main__":
    test_scan()
