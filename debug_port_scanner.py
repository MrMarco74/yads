import requests

target = "parkinson.example.internal"
timeout = 5
verify = False # Testing with and without verification

print(f"Testing {target}...")

try:
    print("--- HTTP ---")
    r = requests.get(f"http://{target}", timeout=timeout, allow_redirects=False)
    print(f"Status: {r.status_code}")
    print(f"Headers: {r.headers}")
except Exception as e:
    print(f"HTTP Error: {e}")

try:
    print("\n--- HTTPS (verify=True) ---")
    r = requests.get(f"https://{target}", timeout=timeout, allow_redirects=False)
    print(f"Status: {r.status_code}")
except Exception as e:
    print(f"HTTPS Verify Error: {e}")

try:
    print("\n--- HTTPS (verify=False) ---")
    r = requests.get(f"https://{target}", timeout=timeout, allow_redirects=False, verify=False)
    print(f"Status: {r.status_code}")
    print(f"Headers: {r.headers}")
except Exception as e:
    print(f"HTTPS No-Verify Error: {e}")
