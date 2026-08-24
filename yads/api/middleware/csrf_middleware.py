"""
Pure-ASGI CSRF middleware.

Validates the CSRF token on all state-changing requests (POST/PUT/PATCH/DELETE).
Reads the token from:
  1. X-CSRF-Token request header  (HTMX, fetch API)
  2. _csrf hidden form field       (regular HTML form submissions)

Requests authenticated via Authorization: Bearer or X-API-Key are exempt on
/api/* paths, plus the one non-/api/ machine-to-machine route
(/tenants/provision) -- those tokens can't be read or set by a cross-site
attacker either, but the exemption is deliberately NOT global: a cookie-
session route must still reject a forged request that merely includes a
fake auth header alongside the victim's session cookie.

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
                scope["csrf_token"] = existing
                await self.app(scope, receive, send)
            return

        # ── Exempt paths (setup flow, static, docs) ──
        if any(path.startswith(p) for p in CSRF_EXEMPT_PREFIXES):
            await self.app(scope, receive, send)
            return

        # ── Bearer-auth / X-API-Key API clients — skip CSRF (API + M2M paths only) ──
        # A request carrying one of these headers can't be forged by a CSRF
        # attack (the attacker's page has no way to read or set the caller's
        # secret key/token) -- but that reasoning only holds for the
        # machine-to-machine surface these headers are meant for. Scoping the
        # exemption prevents a cross-site page from sending a bogus/fake
        # X-API-Key (any non-empty value passes the presence check here) or
        # Authorization header at a cookie-session route to skip CSRF and
        # then get authenticated by the victim's session cookie instead.
        # /tenants/provision is the one non-/api/ route that is also
        # exclusively X-API-Key-authenticated automation (see its own
        # docstring) -- it belongs in this exemption for the same reason
        # /api/* does, not because it happens to share a path prefix.
        if (path.startswith("/api/") or path == "/tenants/provision") and (
            request.headers.get("authorization", "").startswith("Bearer ")
            or request.headers.get("x-api-key", "")
        ):
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

        # Determine the effective scheme: prefer X-Forwarded-Proto (set by a
        # reverse proxy doing TLS termination) over the raw ASGI scheme.
        scheme = scope.get("scheme", "http")
        raw_headers = dict(scope.get("headers", []))
        if b"x-forwarded-proto" in raw_headers:
            if raw_headers[b"x-forwarded-proto"].lower() == b"https":
                scheme = "https"

        # Set Secure only when the connection is actually HTTPS — either directly
        # or via a proxy that sets X-Forwarded-Proto: https.
        # Forcing Secure=True on plain-HTTP connections (no proxy) breaks the
        # cookie for non-localhost FQDNs: browsers silently drop Secure cookies
        # received over HTTP for anything other than localhost.
        secure = (scheme == "https")

        cookie_header = (
            f"{CSRF_COOKIE}={token}; Path=/; SameSite=Strict"
            + ("; Secure" if secure else "")
        )

        scope["csrf_token"] = token

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
