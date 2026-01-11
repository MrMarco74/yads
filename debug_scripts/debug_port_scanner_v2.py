import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

target = "parkinson.example.internal"
timeout = 5
verify = False 

headers = {
    "User-Agent": "Mozilla/5.0 (compatible; YADS/1.0; +http://yads.local)"
}

print(f"Testing {target} with Headers...")

try:
    print("--- HTTP ---")
    r = requests.get(f"http://{target}", timeout=timeout, allow_redirects=False, headers=headers)
    print(f"Status: {r.status_code}")
    print(f"Headers: {r.headers}")
except Exception as e:
    print(f"HTTP Error: {e}")

try:
    print("\n--- HTTPS (verify=False) ---")
    r = requests.get(f"https://{target}", timeout=timeout, allow_redirects=False, verify=False, headers=headers)
    print(f"Status: {r.status_code}")
    print(f"Headers: {r.headers}")
except Exception as e:
    print(f"HTTPS No-Verify Error: {e}")
