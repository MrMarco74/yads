"""
CSRF protection — signed double-submit cookie pattern.

Token format: <random>.HMAC-SHA256(<random>, SECRET_KEY)
The HMAC prevents subdomain-injection attacks: even if an attacker
controls a subdomain and can set cookies for the parent domain,
they cannot forge a valid token without the SECRET_KEY.
"""
import hashlib
import hmac
import secrets

CSRF_COOKIE = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"
CSRF_FIELD = "_csrf"

# Paths that must never be CSRF-checked (setup flow, static assets, API docs)
CSRF_EXEMPT_PREFIXES = (
    "/setup",
    "/static",
    "/docs",
    "/openapi",
    "/redoc",
)

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def _sign(raw: str, secret: str) -> str:
    return hmac.new(secret.encode(), raw.encode(), hashlib.sha256).hexdigest()


def generate_csrf_token() -> str:
    """Return a new signed CSRF token."""
    from yads.config import settings
    raw = secrets.token_urlsafe(32)
    sig = _sign(raw, settings.SECRET_KEY)
    return f"{raw}.{sig}"


def validate_csrf_token(token: str) -> bool:
    """Return True iff the token's HMAC signature is valid."""
    from yads.config import settings
    if not token or "." not in token:
        return False
    raw, _, sig = token.rpartition(".")
    expected = _sign(raw, settings.SECRET_KEY)
    return hmac.compare_digest(expected, sig)
