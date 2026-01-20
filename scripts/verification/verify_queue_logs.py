
import requests

url_logs = "http://localhost:8000/logs"
url_queue = "http://localhost:8000/queue/control" 

print(f"Testing URL: {url_logs}")
headers = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
}
try:
    # Trigger 401/403
    cookies = {"access_token": "invalid_token"}
    response = requests.get(url_logs, headers=headers, cookies=cookies)
    print(f"LOGS: Status Code: {response.status_code}")
    if response.status_code in [401, 403] and "text/html" in response.headers.get("content-type", ""):
        print("SUCCESS: Received HTML error page for logs.")
    else:
        print("FAILURE? Or redirect.")
        
    # Test Queue Control (Requires permissions)
    # GET queue main page doesn't check role, so we check control which does.
    print(f"Testing URL: {url_queue}")
    response = requests.post(url_queue, headers=headers, cookies=cookies, data={"action": "pause"})
    print(f"QUEUE: Status Code: {response.status_code}")
    if response.status_code in [401, 403] and "text/html" in response.headers.get("content-type", ""):
        print("SUCCESS: Received HTML error page for queue control.")
        
except Exception as e:
    print(e)
