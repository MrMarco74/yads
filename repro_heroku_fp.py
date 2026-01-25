import re

# The current regex (from web_analyzer.py)
HEROKU_REGEX = r"(?<!AW-)(?<!G-)(?<!UA-)\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"

# The snippet provided by the user
snippet = """
"keys":[{"hpkePublicKey":{"params":{"aead":"AES_128_GCM","kdf":"HKDF_SHA256","kem":"DHKEM_P256_HKDF_SHA256"},"publicKey":"BPNUToxz9Ch5V6dYX/t6609k12xBDD2yvJGg2FSIL4jU+qf4vEefnk5OUC2sv9/Iesc+NDoTvyjdbZEs6JVG0U8=","version":0},"id":"b5149ce9-8428-4911-b0b0-3d0a32ed1cee"},
{"hpkePublicKey":{...},"id":"b1685c04-8764-468b-94d0-37f7fa3cc7bf"}
"""

def check(text):
    print(f"Testing text: {text[:50]}...")
    matches = re.finditer(HEROKU_REGEX, text)
    found = False
    for match in matches:
        found = True
        print(f"MATCH: {match.group(0)}")
        
        # Simulating context check
        start = match.start()
        # Look back 20 chars
        pre = text[max(0, start-20):start]
        print(f"PRECEDING: ...{pre}")
        
        if re.search(r'["\']?id["\']?\s*:\s*["\']?$', pre):
            print("Action: IGNORE (Context looks like 'id')")
        else:
            print("Action: ALERT")
            
    if not found:
        print("No matches.")

check(snippet)
