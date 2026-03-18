
import os
import sys
from unittest.mock import MagicMock

# Ensure we can import yads
sys.path.append(os.getcwd())

from yads.api.templating import templates

def test_render():
    print("Testing template rendering with csrf_token...")
    mock_request = MagicMock()
    mock_request.scope = {"csrf_token": "test_token_123"}
    
    try:
        # Test main app template
        resp = templates.TemplateResponse("mfa_setup.html", {
            "request": mock_request,
            "secret": "ABCDEF",
            "otp_uri": "otpauth://...",
        })
        print("MFA Setup render successful!")
        if 'value="test_token_123"' in resp.body.decode():
            print("Token correctly injected!")
        else:
            print("Token NOT found in response body!")
            
    except Exception as e:
        print(f"Render failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_render()
