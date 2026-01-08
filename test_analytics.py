import requests
import sys

def test_api():
    base_url = "http://yads-api:8000"
    
    # 1. Get List of targets (from analytics page context? No, difficult to parse HTML)
    # Let's just try thestats endpoint with no filter first
    print("Testing /api/stats/infrastructure (No Filter)...")
    r = requests.get(f"{base_url}/api/stats/infrastructure")
    print(f"Status: {r.status_code}")
    print(r.json())
    
    # 2. Test with a potentially valid ID (e.g., 1)
    print("\nTesting /api/stats/infrastructure?target_id=1 ...")
    r2 = requests.get(f"{base_url}/api/stats/infrastructure?target_id=1")
    print(f"Status: {r2.status_code}")
    print(r2.json())
    
    # 3. Test with invalid ID
    print("\nTesting /api/stats/infrastructure?target_id=99999 ...")
    r3 = requests.get(f"{base_url}/api/stats/infrastructure?target_id=99999")
    print(f"Status: {r3.status_code}")
    # Should be empty but 200
    print(r3.json())

if __name__ == "__main__":
    test_api()
