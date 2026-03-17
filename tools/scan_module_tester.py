#!/usr/bin/env python3
import requests
import json
import time
import sys
import os

# Configuration
BASE_URL = os.getenv("YADS_API_URL", "http://localhost:8085")
USERNAME = "admin"
PASSWORD = "adminAdmin123!" # Using the rotated password
TARGET_DOMAIN = "dvwa.testlab.local"

# Scan Modules to test (Phase 1: CE Baseline)
CE_MODULES = [
    "subdomain_scanner", "dns_scanner", "axfr_scanner", "tld_scanner", 
    "typosquat_scanner", "rpki_scanner", "web_analyzer", "ssl_scanner", 
    "http_headers", "cookie_scanner", "cors_scanner", "csp_scanner", 
    "security_txt", "cert_mismatch", "email_security", "dsgvo_scanner", 
    "git_exposure", "seed_files_scanner", "metadata_scanner", 
    "shodan_censys", "js_secrets", "wayback_scanner", "external_resources", 
    "cloud_scanner", "threat_intel", "subdomain_takeover", "nuclei_scanner", 
    "banner_grabber", "port_scanner", "nmap_scanner", "crawler", 
    "content_discovery", "visual_osint", "deception_detector", 
    "infrastructure_scanner", "waf_detector", "asn_scanner", 
    "login_scanner", "ipv6_scanner", "open_redirect_scanner", 
    "dns_history_scanner", "phishing_scanner", "tls_deep_scanner", 
    "ct_monitor"
]

def main():
    session = requests.Session()
    
    print(f"[*] Fetching login page for CSRF token...")
    get_resp = session.get(f"{BASE_URL}/login")
    csrf_token = session.cookies.get("csrf_token")
    
    import re
    match = re.search(r'name="_csrf" value="([^"]+)"', get_resp.text)
    if not match:
        print("[!] CSRF token not found in login page")
        # Fallback to cookie if hidden field is injected by JS (Playwright found this earlier)
        # But here we are using requests, so we might need to be more clever if it's JS-injected.
        # Wait, if it's JS injected, requests won't see it in get_resp.text.
        # However, the CSRFMiddleware might accept it from the cookie or a header.
        csrf_token_field = csrf_token
    else:
        csrf_token_field = match.group(1)

    print(f"[*] Logging in as {USERNAME}...")
    login_resp = session.post(f"{BASE_URL}/login", data={
        "username": USERNAME,
        "password": PASSWORD,
        "_csrf": csrf_token_field
    }, headers={
        "X-CSRF-Token": csrf_token
    }, allow_redirects=False)
    
    if login_resp.status_code not in [200, 303]:
        print(f"[!] Login failed with status {login_resp.status_code}")
        sys.exit(1)
    print("[+] Login successful.")

    # 1. Ensure Target Exists
    def post_with_csrf(url, data=None):
        csrf = session.cookies.get("csrf_token")
        return session.post(url, data=data, headers={"X-CSRF-Token": csrf}, allow_redirects=False)

    print(f"[*] Ensuring target {TARGET_DOMAIN} exists...")
    # Try adding it (will fail if exists, but we handle 403/other)
    add_resp = post_with_csrf(f"{BASE_URL}/targets/add", data={"domain": TARGET_DOMAIN})
    print(f"[+] Target add response: {add_resp.status_code}")

    # Find the target ID
    print(f"[*] Searching for target ID...")
    table_resp = session.get(f"{BASE_URL}/targets/table", params={"filter_domain": TARGET_DOMAIN})
    
    # Debug: Print a snippet of the table response
    if "dvwa.testlab.local" not in table_resp.text:
        print("[!] Target domain not found in table view. Internal HTML:")
        print(table_resp.text[:1000])
    
    match = re.search(r'/targets/(\d+)', table_resp.text)
    if not match:
        # Try a different pattern for target ID
        match = re.search(r'data-target-id="(\d+)"', table_resp.text)
    
    if not match:
        print("[!] Could not find target ID for dvwa.testlab.local")
        sys.exit(1)
    
    target_id = match.group(1)
    print(f"[+] Found Target ID: {target_id}")

    # 2. Trigger Scans
    print(f"[*] Triggering {len(CE_MODULES)} modules for target {target_id}...")
    
    results = []
    for module in CE_MODULES:
        print(f"[*] Triggering {module}...")
        resp = post_with_csrf(f"{BASE_URL}/targets/{target_id}/scan", data={
            "scan_types": [module],
            "scan_priority": 5
        })
        
        if resp.status_code == 303:
            print(f"[+] {module} queued successfully.")
            results.append({"module": module, "status": "queued"})
        else:
            print(f"[!] {module} failed to queue: {resp.status_code}")
            results.append({"module": module, "status": "failed", "code": resp.status_code})
        
        time.sleep(0.5)

    # 3. Final Report (Quick Summary)
    print("\n" + "="*40)
    print("CE MODULE TEST SUMMARY")
    print("="*40)
    for res in results:
        status = res["status"]
        mod = res["module"]
        print(f"[{'OK' if status == 'queued' else '!!'}] {mod:30} : {status}")
    print("="*40)

if __name__ == "__main__":
    main()
