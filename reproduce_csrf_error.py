import os
import sys

# Add current directory to path
sys.path.append(os.getcwd())

from yads.api.templating import templates
from fastapi import Request

# Mock request
scope = {
    "type": "http",
    "method": "GET",
    "path": "/mfa/setup",
    "headers": [],
    "csrf_token": "test-token"
}
request = Request(scope)

try:
    print("Testing template rendering...")
    response = templates.TemplateResponse("mfa_setup.html", {
        "request": request,
        "secret": "JBSWY3DPEHPK3PXP",
        "otp_uri": "otpauth://totp/YADS:test?secret=JBSWY3DPEHPK3PXP&issuer=YADS"
    })
    print("SUCCESS: Template rendered without error.")
except Exception as e:
    print(f"FAILED: {e}")
    import traceback
    traceback.print_exc()
