"""
Password Spray Surface Mapper (#47)

Maps authentication surfaces that could be targeted in password spray attacks:
  - Discovers all login endpoints (OAuth, SAML, Basic Auth, Forms)
  - Detects Microsoft 365 / Azure AD integration (user enumeration risk)
  - Detects Google Workspace login integration
  - Checks for lockout policy hints (X-RateLimit headers, lockout messages)
  - Identifies externally exposed admin panels
  - Checks for legacy auth protocols (NTLM, Basic Auth over HTTP)
  - Autodiscover endpoints (M365 user enumeration)
  - Detects if MFA is enforced (or not)

Passive surface mapping only — does NOT attempt any credentials.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin

import requests

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

TIMEOUT = 10
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; YADS-Security-Scanner/1.0)",
    "Accept": "text/html,application/xhtml+xml,*/*",
}

# M365 / Azure AD indicators
AZURE_PATHS = [
    "/autodiscover/autodiscover.xml",
    "/.well-known/openid-configuration",
    "/adfs/ls",
    "/adfs/ls/idpinitiatedsignon.aspx",
    "/OWA",
    "/EWS/Exchange.asmx",
    "/Microsoft-Server-ActiveSync",
    "/mapi",
]

# Common SSO / IdP paths
SSO_PATHS = [
    "/saml/login", "/saml/sso", "/sso", "/oauth/authorize",
    "/oauth2/authorize", "/auth/saml", "/login/saml",
    "/.well-known/openid-configuration",
    "/connect/authorize",
]

# Login paths to check for spray surface
LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/auth", "/admin/login",
    "/wp-login.php", "/wp-admin", "/user/login", "/account/login",
    "/api/auth", "/api/v1/auth", "/api/login",
]

# Indicators of MFA/lockout in page content
MFA_RE = re.compile(r"(two.factor|2fa|mfa|authenticator|totp|otp|verification code)", re.IGNORECASE)
LOCKOUT_RE = re.compile(r"(too many attempt|account.locked|temporarily.blocked|rate.limit|cooldown)", re.IGNORECASE)
NTLM_RE = re.compile(r"NTLM|Negotiate", re.IGNORECASE)

# M365 user enumeration via GetCredentialType
M365_ENUM_URL = "https://login.microsoftonline.com/common/GetCredentialType"
M365_TENANT_URL = "https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"


def _clean_base(target: str) -> str:
    t = target.lower().strip()
    if not t.startswith("http"):
        t = "https://" + t
    return t.rstrip("/")


def _get(url: str, allow_redirects: bool = True) -> Optional[requests.Response]:
    try:
        return requests.get(url, timeout=TIMEOUT, headers=HEADERS, verify=False,
                            allow_redirects=allow_redirects)
    except Exception:
        return None


def _check_m365_tenant(domain: str) -> Optional[Dict]:
    """Check if domain uses Microsoft 365 / Azure AD."""
    try:
        r = requests.get(
            M365_TENANT_URL.format(domain=domain),
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            tenant_id = data.get("issuer", "").split("/")[3] if "/" in data.get("issuer", "") else None
            return {
                "uses_m365": True,
                "tenant_id": tenant_id,
                "token_endpoint": data.get("token_endpoint", ""),
                "authorization_endpoint": data.get("authorization_endpoint", ""),
            }
    except Exception:
        pass
    return None


def _check_autodiscover(domain: str) -> Optional[Dict]:
    """Check autodiscover endpoint (reveals Exchange/M365 usage)."""
    urls = [
        f"https://autodiscover.{domain}/autodiscover/autodiscover.xml",
        f"https://{domain}/autodiscover/autodiscover.xml",
    ]
    for url in urls:
        resp = _get(url)
        if resp and resp.status_code in (200, 401, 403):
            return {
                "url": url,
                "status": resp.status_code,
                "auth_required": resp.status_code == 401,
                "ntlm": bool(NTLM_RE.search(resp.headers.get("WWW-Authenticate", ""))),
            }
    return None


def _check_basic_auth(domain: str) -> List[Dict]:
    """Find endpoints using HTTP Basic Auth."""
    basic_auth_endpoints = []
    paths = ["/admin", "/management", "/api", "/console", "/secure"]
    base = f"https://{domain}"
    for path in paths:
        resp = _get(urljoin(base + "/", path.lstrip("/")), allow_redirects=False)
        if resp and resp.status_code == 401:
            www_auth = resp.headers.get("WWW-Authenticate", "")
            if "Basic" in www_auth:
                basic_auth_endpoints.append({
                    "path": path,
                    "realm": re.search(r'realm="([^"]+)"', www_auth, re.IGNORECASE).group(1)
                    if re.search(r'realm="([^"]+)"', www_auth, re.IGNORECASE) else "",
                })
    return basic_auth_endpoints


def _check_rate_limiting(base: str) -> bool:
    """Check if login page returns rate-limit headers."""
    login_url = urljoin(base + "/", "login")
    resp = _get(login_url)
    if resp:
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        if any(h in headers_lower for h in ["x-ratelimit-limit", "retry-after", "x-rate-limit"]):
            return True
        if LOCKOUT_RE.search(resp.text[:5000]):
            return True
    return False


def _check_mfa_enforced(base: str) -> Optional[bool]:
    """Check login pages for MFA indicators."""
    for path in ["/login", "/signin", "/auth"]:
        resp = _get(urljoin(base + "/", path.lstrip("/")))
        if resp and resp.status_code == 200:
            if MFA_RE.search(resp.text[:20000]):
                return True
    return False


def _check_sso_endpoints(base: str) -> List[Dict]:
    """Discover SSO / OAuth / SAML endpoints."""
    found = []
    for path in SSO_PATHS:
        resp = _get(urljoin(base + "/", path.lstrip("/")))
        if resp and resp.status_code in (200, 302, 301):
            found.append({
                "path": path,
                "status": resp.status_code,
                "type": "SAML" if "saml" in path.lower() else "OAuth/OIDC" if "oauth" in path.lower() or "openid" in path.lower() else "SSO",
            })
    return found


class PasswordSprayMapper(BaseScannerModule):
    """Password spray attack surface mapping."""

    @property
    def module_name(self) -> str:
        return "password_spray_mapper"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        base = _clean_base(target)
        domain = base.replace("https://", "").replace("http://", "")

        result: Dict[str, Any] = {
            "domain": domain,
            "m365_tenant": None,
            "autodiscover": None,
            "sso_endpoints": [],
            "basic_auth_endpoints": [],
            "login_surfaces": [],
            "rate_limiting_detected": False,
            "mfa_detected": None,
            "findings": [],
            "summary": {
                "score": 100,
                "spray_surface": "unknown",
                "auth_systems": [],
                "issues": 0,
            },
        }

        findings: List[Dict] = []
        score = 100
        auth_systems: List[str] = []

        # 1. Check M365/Azure AD
        m365 = _check_m365_tenant(domain)
        result["m365_tenant"] = m365
        if m365:
            auth_systems.append("Microsoft 365 / Azure AD")

        # 2. Autodiscover (Exchange/M365)
        autodiscover = _check_autodiscover(domain)
        result["autodiscover"] = autodiscover
        if autodiscover:
            if "Microsoft 365 / Azure AD" not in auth_systems:
                auth_systems.append("Microsoft Exchange")

        # 3. SSO endpoints
        sso = _check_sso_endpoints(base)
        result["sso_endpoints"] = sso
        for ep in sso:
            stype = ep.get("type", "SSO")
            if stype not in auth_systems:
                auth_systems.append(stype)

        # 4. Basic Auth
        basic_auth = _check_basic_auth(domain)
        result["basic_auth_endpoints"] = basic_auth

        # 5. Rate limiting
        rate_limited = _check_rate_limiting(base)
        result["rate_limiting_detected"] = rate_limited

        # 6. MFA detection
        mfa = _check_mfa_enforced(base)
        result["mfa_detected"] = mfa

        # 7. Login surfaces count
        login_count = 0
        for path in LOGIN_PATHS[:8]:
            resp = _get(urljoin(base + "/", path.lstrip("/")))
            if resp and resp.status_code in (200, 401):
                login_count += 1
                result["login_surfaces"].append({"path": path, "status": resp.status_code})

        result["summary"]["auth_systems"] = auth_systems

        # --- Findings ---
        if m365:
            findings.append({
                "severity": "info",
                "title": "Microsoft 365 / Azure AD tenant detected",
                "description": (
                    f"The domain uses Microsoft 365 authentication. "
                    "Azure AD accounts are a prime target for password spray attacks via "
                    "the Microsoft login endpoints. Ensure MFA is enforced for all accounts."
                ),
                "tenant_id": m365.get("tenant_id"),
            })
            # Check for user enumeration via GetCredentialType
            try:
                r = requests.post(
                    M365_ENUM_URL,
                    json={"Username": f"nonexistent_yads_test_user@{domain}", "isOtherIdpSupported": True},
                    timeout=TIMEOUT,
                )
                if r.status_code == 200:
                    data = r.json()
                    if data.get("IfExistsResult") in (0, 1):
                        findings.append({
                            "severity": "medium",
                            "title": "Microsoft 365 user enumeration possible via GetCredentialType",
                            "description": (
                                "The Microsoft 365 GetCredentialType API can be used to enumerate valid "
                                "email addresses before launching password spray attacks. "
                                "This is a Microsoft-level control, but attackers can pre-filter valid targets."
                            ),
                        })
                        score -= 15
            except Exception:
                pass

        if autodiscover:
            sev = "high" if autodiscover.get("ntlm") else "medium"
            findings.append({
                "severity": sev,
                "title": f"Autodiscover endpoint exposed ({autodiscover['url']})",
                "description": (
                    "Exchange Autodiscover endpoint is accessible. "
                    + ("NTLM authentication detected — vulnerable to NTLM relay and hash capture attacks. " if autodiscover.get("ntlm") else "")
                    + "Password spray via EWS/ActiveSync is possible against this endpoint."
                ),
                "url": autodiscover.get("url"),
                "ntlm": autodiscover.get("ntlm"),
            })
            score -= 25 if sev == "high" else 15

        if basic_auth:
            sev = "high"
            paths_str = ", ".join(e["path"] for e in basic_auth[:3])
            findings.append({
                "severity": sev,
                "title": f"HTTP Basic Authentication endpoints: {paths_str}",
                "description": (
                    "Basic Authentication endpoints are exposed. These accept credentials as "
                    "Base64-encoded username:password in headers — easily brute-forced and "
                    "do not support lockout policies in most implementations."
                ),
                "endpoints": basic_auth,
            })
            score -= 25

        if not rate_limited and login_count > 0:
            findings.append({
                "severity": "medium",
                "title": "No rate limiting or lockout policy detected on login endpoints",
                "description": (
                    "Login endpoints do not appear to implement rate limiting. "
                    "This makes password spray attacks more effective — an attacker can "
                    "test many passwords without triggering account lockouts."
                ),
            })
            score -= 20

        if mfa is False and login_count > 0:
            findings.append({
                "severity": "medium",
                "title": "No MFA indicators found on login page(s)",
                "description": (
                    "Login pages show no evidence of multi-factor authentication. "
                    "Without MFA, successful password spray immediately yields account access."
                ),
            })
            score -= 15
        elif mfa:
            findings.append({
                "severity": "info",
                "title": "MFA indicators detected on login page",
                "description": "Multi-factor authentication appears to be implemented, reducing spray attack effectiveness.",
            })

        if not auth_systems and not login_count:
            findings.append({
                "severity": "info",
                "title": "No significant authentication surfaces discovered",
                "description": "No externally exposed login endpoints or auth systems were identified.",
            })

        spray_surface = "high" if (basic_auth or (autodiscover and autodiscover.get("ntlm"))) else \
                        "medium" if (login_count > 0 and not rate_limited) else "low"
        result["summary"]["spray_surface"] = spray_surface
        result["summary"]["score"] = max(0, score)
        result["summary"]["issues"] = len([f for f in findings if f["severity"] not in ("info",)])
        result["findings"] = findings
        return result
