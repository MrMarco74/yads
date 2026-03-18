"""
Pure-ASGI CSRF middleware.

Validates the CSRF token on all state-changing requests (POST/PUT/PATCH/DELETE).
Reads the token from:
  1. X-CSRF-Token request header  (HTMX, fetch API)
  2. _csrf hidden form field       (regular HTML form submissions)

On GET requests, auto-sets the csrf_token cookie if it is absent so that
the page's JavaScript can read it and inject it into forms / HTMX headers.

Body double-read problem is solved by replacing the ASGI receive callable
with a replay function after the body has been read once.
"""
import hmac
import logging
import re

from starlette.requests import Request
from starlette.responses import HTMLResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from yads.core.csrf import (
    CSRF_COOKIE,
    CSRF_EXEMPT_PREFIXES,
    CSRF_FIELD,
    CSRF_HEADER,
    _SAFE_METHODS,
    generate_csrf_token,
    validate_csrf_token,
)

logger = logging.getLogger("yads.csrf")

# Regex to extract _csrf value from a multipart body:
# matches: Content-Disposition: form-data; name="_csrf"\r\n\r\nVALUE
_MULTIPART_CSRF_RE = re.compile(
    rb'Content-Disposition:\s*form-data;\s*name=["\']?_csrf["\']?[^\r\n]*\r\n\r\n([^\r\n]+)',
    re.IGNORECASE,
)


class CSRFMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        method = request.method
        path = request.url.path

        # ── GET / safe methods: pass through, set cookie if absent OR invalid ──
        # An existing cookie may be stale (signed with an old SECRET_KEY after a reinstall).
        # Always validate and replace it if it fails — this is the key fix for the "CSRF
        # cookie missing or invalid" error that returns after fresh installs.
        if method in _SAFE_METHODS:
            existing = request.cookies.get(CSRF_COOKIE, "")
            if not existing or not validate_csrf_token(existing):
                if existing:
                    logger.info("CSRF: replacing stale/invalid cookie on GET %s", path)
                await self._pass_set_cookie(scope, receive, send)
            else:
                await self.app(scope, receive, send)
            return

        # ── Exempt paths (setup flow, static, docs) ──
        if any(path.startswith(p) for p in CSRF_EXEMPT_PREFIXES):
            await self.app(scope, receive, send)
            return

        # ── Bearer-auth API clients — skip CSRF ──
        if request.headers.get("authorization", "").startswith("Bearer "):
            await self.app(scope, receive, send)
            return

        # ── Validate cookie ──
        cookie_token = request.cookies.get(CSRF_COOKIE, "")
        if not cookie_token or not validate_csrf_token(cookie_token):
            logger.warning("CSRF: missing or invalid cookie for %s %s", method, path)
            await self._reject(scope, send, "CSRF cookie missing or invalid.")
            return

        # ── Check header first (HTMX / fetch) ──
        submitted = request.headers.get(CSRF_HEADER, "")
        if submitted:
            if not hmac.compare_digest(cookie_token, submitted):
                logger.warning("CSRF: header mismatch for %s %s", method, path)
                await self._reject(scope, send, "CSRF validation failed.")
                return
            await self.app(scope, receive, send)
            return

        # ── No header — read body and check form field ──
        body = await request.body()

        content_type = request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in content_type:
            from urllib.parse import parse_qs
            params = parse_qs(body.decode(errors="replace"), keep_blank_values=True)
            submitted = params.get(CSRF_FIELD, [""])[0]
        elif "multipart/form-data" in content_type:
            m = _MULTIPART_CSRF_RE.search(body)
            submitted = m.group(1).decode(errors="replace").strip() if m else ""

        if not submitted or not hmac.compare_digest(cookie_token, submitted):
            logger.warning("CSRF: form field mismatch for %s %s", method, path)
            await self._reject(scope, send, "CSRF validation failed.")
            return

        # Body was consumed — replay it for downstream handlers
        async def replay_receive() -> dict:
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay_receive, send)

    async def _pass_set_cookie(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        """Pass the request through and attach a fresh CSRF cookie to the response."""
        from yads.config import settings

        token = generate_csrf_token()

        # Determine if we should set the Secure flag.
        # 1. Check if the current request is HTTPS (direct or via reverse proxy)
        scheme = scope.get("scheme", "http")
        headers = dict(scope.get("headers", []))
        if b"x-forwarded-proto" in headers:
            if headers[b"x-forwarded-proto"].lower() == b"https":
                scheme = "https"

        # 2. Secure flag:
        # - If DISABLE_HTTPS_ONLY is True (dev/installer fallback):
        #   Only set Secure if we are actually on HTTPS.
        # - If DISABLE_HTTPS_ONLY is False (production default):
        #   Force Secure even if the internal connection is HTTP (expected behind proxy).
        if settings.DISABLE_HTTPS_ONLY:
            secure = (scheme == "https")
        else:
            secure = True

        cookie_header = (
            f"{CSRF_COOKIE}={token}; Path=/; SameSite=Strict"
            + ("; Secure" if secure else "")
        )

        async def send_with_cookie(message: dict) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((b"set-cookie", cookie_header.encode()))
                message = dict(message, headers=headers)
            await send(message)

        await self.app(scope, receive, send_with_cookie)

    @staticmethod
    async def _reject(scope: Scope, send: Send, detail: str) -> None:
        async def dummy_receive() -> dict:
            return {"type": "http.disconnect"}

        response = HTMLResponse(detail, status_code=403)
        await response(scope, dummy_receive, send)
