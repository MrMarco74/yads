
import requests
import sys

# Since I cannot easily log in and get a real token without Selenium or complex setup in this script,
# I will test the EXCEPTION HANDLER behavior by triggering a 403/401.

# 1. Test Unauthenticated Request (expecting 403/401 HTML page for browser-like request)
url = "http://localhost:8000/targets/bulk/scan"
headers = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
}

print(f"Testing URL: {url}")
try:
    # This should trigger 401/403 because we have no token.
    # The login_required_handler redirects to /login usually (307/303).
    # But RoleChecker might raise 403 directly if user is logged in but wrong role.
    # Let's try to mock a user with WRONG role if possible? Hard without DB access.
    
    # Wait, the `login_required_handler` I didn't touch, it redirects to /login.
    # But `RoleChecker` raises HTTPException(403) if role is mismatch.
    
    # To test the new handler, I need to cause an HTTPException that is NOT LoginRequired.
    # I can try to hit an endpoint that raises HTTPException directly?
    # Or rely on the fact that if I send a bad token, `get_current_user` raises 401 HTTPException.
    
    # Let's send a BAD token.
    cookies = {"access_token": "invalid_token"}
    response = requests.post(url, headers=headers, cookies=cookies)
    
    print(f"Status Code: {response.status_code}")
    print(f"Content-Type: {response.headers.get('content-type')}")
    
    if response.status_code in [401, 403] and "text/html" in response.headers.get("content-type", ""):
        print("SUCCESS: Received HTML error page for 401/403.")
        if "Authentication Required" in response.text or "Access Denied" in response.text:
             print("SUCCESS: Page content seems correct.")
        else:
             print("WARNING: Page content might not contain expected title.")
             # print(response.text[:500])
             
    elif response.status_code in [302, 303, 307]:
        print("Got Redirect (likely to login), which is also acceptable for unauth.")
        
    else:
        print("FAILURE: Did not receive expected HTML error page.")
        # print(response.text)

except Exception as e:
    print(f"Error connecting: {e}")
    print("Ensure server is running.")

