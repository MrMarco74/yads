"""
Session auth for the support portal web UI.

The session password IS the ADMIN_TOKEN.  On successful login a signed
cookie is issued (HMAC-SHA256, 8-hour TTL).  The middleware in main.py
enforces this for all non-public routes.
"""
import hashlib
import hmac
import time

COOKIE_NAME = "support_session"
SESSION_TTL = 8 * 3600  # 8 hours

_SECRET: str = ""


def init_secret(secret: str) -> None:
    global _SECRET
    _SECRET = secret


def make_session_token() -> str:
    ts = str(int(time.time()))
    sig = hmac.new(_SECRET.encode(), ts.encode(), hashlib.sha256).hexdigest()
    return f"{ts}.{sig}"


def verify_session_token(token: str) -> bool:
    if not _SECRET or not token:
        return False
    try:
        ts_str, sig = token.rsplit(".", 1)
        expected = hmac.new(_SECRET.encode(), ts_str.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False
        if time.time() - int(ts_str) > SESSION_TTL:
            return False
        return True
    except Exception:
        return False
