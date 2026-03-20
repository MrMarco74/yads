#!/usr/bin/env python3
import subprocess
import json
import time
import sys
import os

def run_command(cmd, input_data=None):
    print(f"Executing: {' '.join(cmd)}")
    stdin = subprocess.PIPE if input_data else None
    process = subprocess.Popen(cmd, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if input_data:
        stdout, _ = process.communicate(input=input_data)
        print(stdout)
    else:
        for line in process.stdout:
            print(line.strip())
        process.wait()
    return process.returncode == 0

def wait_for_healthy(url, timeout=60):
    print(f"Waiting for {url} to be healthy...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            # Use curl to check health
            res = subprocess.run(["curl", "-s", "-k", f"{url}/health"], capture_output=True, text=True)
            if res.returncode == 0 and '"status":"ok"' in res.stdout:
                print("Service is healthy!")
                return True
        except Exception:
            pass
        time.sleep(2)
    print("Timeout waiting for healthy service.")
    return False

def test_flow(name, mode, user, password, port):
    print(f"\n" + "="*50)
    print(f"RUNNING TEST: {name}")
    print("="*50)
    
    setup_data = {
        "host": "localhost",
        "api_port": port,
        "admin_user": user,
        "admin_pass": password,
        "install_mode": mode,
        "do_backup": False,
        "license_key": "TEST-LICENSE-123"
    }
    
    # 1. Run Installer
    if not run_command(["python3", "run_installer_headless.py", json.dumps(setup_data)]):
        print(f"FAILED: Installer failed for {name}")
        return False
        
    # 2. Wait for healthy
    url = f"http://localhost:{port}"
    if not wait_for_healthy(url):
        print(f"FAILED: Service not healthy for {name}")
        return False
        
    # 3. Verify Login
    if not run_command(["python3", "verify_login.py", f"{url}/login", user, password]):
        print(f"FAILED: Login verification failed for {name}")
        return False
        
    print(f"SUCCESS: Test {name} passed!")
    return True

if __name__ == "__main__":
    USER = "yadsadminlocal"
    PASS = "Alpha0!AAAAA"
    PORT = "8085"
    
    results = {}
    
    # Run 1: New Installation
    results["Neuinstallation"] = test_flow("Neuinstallation", "reinstall", USER, PASS, PORT)
    
    # Run 2: Update (Upgrade)
    if results["Neuinstallation"]:
        results["Update"] = test_flow("Update (Upgrade)", "upgrade", USER, PASS, PORT)
    else:
        results["Update"] = "SKIPPED (Fresh failed)"
        
    print("\n" + "#"*50)
    print("FINAL RESULTS")
    print("#"*50)
    for k, v in results.items():
        print(f"{k}: {'OK' if v is True else 'FAILED' if v is False else v}")
    
    sys.exit(0 if all(r is True for r in results.values() if isinstance(r, bool)) else 1)
