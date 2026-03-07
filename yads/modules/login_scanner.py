"""
Login & Auth Surface Scanner (#12)

Discovers login endpoints and assesses their security posture:
- Common login/admin URLs probing
- Authentication mechanism detection (form, basic auth, OAuth, SSO)
- Missing security headers on login pages (HSTS, CSP, X-Frame-Options)
- Exposed admin interfaces
- Default/common credential hints
- Password reset endpoint discovery

Does NOT attempt authentication — passive surface mapping only.
"""

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

TIMEOUT = 10
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; YADS-Security-Scanner/1.0)",
    "Accept": "text/html,application/xhtml+xml,*/*",
}

# Paths to probe for login surfaces
LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/auth", "/authenticate",
    "/admin", "/admin/login", "/administrator", "/wp-login.php",
    "/wp-admin", "/dashboard", "/console", "/portal", "/panel",
    "/account/login", "/user/login", "/users/sign_in",
    "/secure", "/private", "/member", "/members",
    "/backend", "/cpanel", "/webmail",
    "/api/login", "/api/auth", "/api/v1/auth", "/api/v1/login",
    "/oauth/authorize", "/oauth2/authorize", "/saml/login",
    "/.well-known/openid-configuration",
]

# Password reset paths
RESET_PATHS = [
    "/forgot-password", "/reset-password", "/password/reset",
    "/account/forgot", "/user/password", "/users/password/new",
    "/auth/forgot", "/recover",
]

# Admin/sensitive paths
ADMIN_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/phpmyadmin",
    "/adminer", "/cpanel", "/plesk", "/_admin", "/manage",
    "/management", "/controlpanel", "/control-panel",
]

_FORM_RE = re.compile(r'<form[^>]*method=["\']?post["\']?', re.IGNORECASE)
_PASSWORD_RE = re.compile(r'<input[^>]*type=["\']?password["\']?', re.IGNORECASE)
_OAUTH_RE = re.compile(r'(oauth|google.*sign|facebook.*login|github.*auth|microsoft.*login)', re.IGNORECASE)
_SAML_RE = re.compile(r'(saml|sso|single.sign.on)', re.IGNORECASE)
_TOTP_RE = re.compile(r'(two.factor|2fa|totp|authenticator|mfa)', re.IGNORECASE)
_CAPTCHA_RE = re.compile(r'(captcha|recaptcha|hcaptcha|turnstile)', re.IGNORECASE)
_CSRF_RE = re.compile(r'(csrf|_token|authenticity_token|__requestverificationtoken)', re.IGNORECASE)


def _clean_base(target: str) -> str:
    t = target.lower().strip()
    if not t.startswith("http"):
        t = "https://" + t
    return t.rstrip("/")


def _probe(base: str, path: str) -> Optional[requests.Response]:
    url = urljoin(base + "/", path.lstrip("/"))
    try:
        r = requests.get(
            url, timeout=TIMEOUT, allow_redirects=True,
            headers=HEADERS, verify=False,
        )
        return r
    except Exception:
        return None


def _check_security_headers(resp: requests.Response) -> List[Dict]:
    issues = []
    h = {k.lower(): v for k, v in resp.headers.items()}

    if "strict-transport-security" not in h:
        issues.append({"header": "HSTS", "severity": "medium", "detail": "Missing HSTS header on login page"})
    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
        issues.append({"header": "X-Frame-Options", "severity": "low", "detail": "Login page may be embeddable (clickjacking risk)"})
    if "content-security-policy" not in h:
        issues.append({"header": "CSP", "severity": "low", "detail": "No Content-Security-Policy on login page"})
    if "referrer-policy" not in h:
        issues.append({"header": "Referrer-Policy", "severity": "info", "detail": "No Referrer-Policy — credentials may leak via referrer"})

    return issues


def _analyze_login_page(resp: requests.Response, path: str) -> Dict:
    body = resp.text[:20000]
    page: Dict = {
        "path": path,
        "url": resp.url,
        "status": resp.status_code,
        "has_password_field": bool(_PASSWORD_RE.search(body)),
        "has_post_form": bool(_FORM_RE.search(body)),
        "has_csrf": bool(_CSRF_RE.search(body)),
        "has_captcha": bool(_CAPTCHA_RE.search(body)),
        "has_oauth": bool(_OAUTH_RE.search(body)),
        "has_saml": bool(_SAML_RE.search(body)),
        "has_2fa_hint": bool(_TOTP_RE.search(body)),
        "basic_auth": resp.status_code == 401,
        "security_header_issues": _check_security_headers(resp),
    }
    return page


class LoginScanner(BaseScannerModule):
    """Discovers and assesses login/auth surfaces without attempting authentication."""

    @property
    def module_name(self) -> str:
        return "login_scanner"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        base = _clean_base(target)
        if base.startswith("http://"):
            # Try HTTPS first
            https_base = base.replace("http://", "https://")
        else:
            https_base = base

        result: Dict[str, Any] = {
            "domain": base.replace("https://", "").replace("http://", ""),
            "login_pages": [],
            "admin_pages": [],
            "reset_pages": [],
            "findings": [],
            "summary": {
                "score": 100,
                "login_count": 0,
                "admin_count": 0,
                "has_2fa": False,
                "has_csrf": False,
                "exposed_admin": False,
            },
        }

        findings: List[Dict] = []
        login_pages = []
        admin_pages = []
        reset_pages = []

        # Probe login paths
        for path in LOGIN_PATHS:
            resp = _probe(https_base, path)
            if resp is None:
                continue
            if resp.status_code in (200, 401) or (
                resp.status_code in (301, 302) and
                any(kw in resp.headers.get("Location", "") for kw in ["login", "auth", "signin"])
            ):
                page = _analyze_login_page(resp, path)
                if page["has_password_field"] or page["basic_auth"] or page["has_oauth"]:
                    login_pages.append(page)

        # Probe admin paths
        for path in ADMIN_PATHS:
            resp = _probe(https_base, path)
            if resp is None:
                continue
            if resp.status_code in (200, 401, 403):
                page = _analyze_login_page(resp, path)
                admin_pages.append({**page, "accessible": resp.status_code != 403})

        # Probe reset paths
        for path in RESET_PATHS:
            resp = _probe(https_base, path)
            if resp is None:
                continue
            if resp.status_code == 200:
                reset_pages.append({
                    "path": path,
                    "url": resp.url,
                    "status": resp.status_code,
                })

        result["login_pages"] = login_pages
        result["admin_pages"] = admin_pages
        result["reset_pages"] = reset_pages
        result["summary"]["login_count"] = len(login_pages)
        result["summary"]["admin_count"] = len(admin_pages)
        result["summary"]["has_2fa"] = any(p.get("has_2fa_hint") for p in login_pages)
        result["summary"]["has_csrf"] = all(p.get("has_csrf") for p in login_pages) if login_pages else False
        result["summary"]["exposed_admin"] = any(p.get("accessible") for p in admin_pages)

        score = 100

        # --- Findings ---
        if not login_pages:
            findings.append({
                "severity": "info",
                "title": "No common login pages found",
                "description": "No login endpoints were discovered at common paths.",
            })
        else:
            findings.append({
                "severity": "info",
                "title": f"{len(login_pages)} login endpoint(s) discovered",
                "description": f"Found login surfaces at: {', '.join(p['path'] for p in login_pages[:5])}",
                "paths": [p["path"] for p in login_pages],
            })

        # Admin exposed
        exposed_admin = [p for p in admin_pages if p.get("accessible") and p["status"] == 200]
        if exposed_admin:
            findings.append({
                "severity": "high",
                "title": f"Exposed admin interface(s): {', '.join(p['path'] for p in exposed_admin[:3])}",
                "description": "Admin panels are publicly accessible. These should be restricted to internal networks.",
                "paths": [p["path"] for p in exposed_admin],
            })
            score -= 35

        # Missing security headers on login pages
        all_header_issues: List[Dict] = []
        for p in login_pages:
            all_header_issues.extend(p.get("security_header_issues", []))

        unique_header_issues = {i["header"]: i for i in all_header_issues}
        for header, issue in unique_header_issues.items():
            findings.append({
                "severity": issue["severity"],
                "title": f"Login page missing {header}",
                "description": issue["detail"],
            })
            if issue["severity"] == "medium":
                score -= 15
            elif issue["severity"] == "low":
                score -= 5

        # No CSRF protection
        pages_with_form = [p for p in login_pages if p.get("has_post_form")]
        pages_without_csrf = [p for p in pages_with_form if not p.get("has_csrf")]
        if pages_without_csrf:
            findings.append({
                "severity": "medium",
                "title": f"Login form(s) without CSRF token ({len(pages_without_csrf)} page(s))",
                "description": "Login forms without CSRF tokens may be vulnerable to cross-site request forgery.",
                "paths": [p["path"] for p in pages_without_csrf],
            })
            score -= 15

        # No 2FA hint
        if login_pages and not result["summary"]["has_2fa"]:
            findings.append({
                "severity": "low",
                "title": "No two-factor authentication (2FA) detected",
                "description": "No 2FA mechanisms (TOTP, MFA prompts) were detected on login pages.",
            })
            score -= 10

        # No captcha
        pages_without_captcha = [p for p in login_pages if not p.get("has_captcha")]
        if len(pages_without_captcha) == len(login_pages) and login_pages:
            findings.append({
                "severity": "info",
                "title": "No CAPTCHA on login page(s)",
                "description": "Login pages have no visible CAPTCHA protection against brute force.",
            })

        # Password reset available (good thing — informational)
        if reset_pages:
            findings.append({
                "severity": "info",
                "title": f"Password reset endpoint found at {reset_pages[0]['path']}",
                "description": "A password reset flow was discovered.",
            })

        result["findings"] = findings
        result["summary"]["score"] = max(0, score)
        return result
