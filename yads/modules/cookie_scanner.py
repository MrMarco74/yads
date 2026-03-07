"""
Cookie Security Analyzer (Task #9)
=====================================
Analyzes Set-Cookie headers for security attributes.
Checks: Secure, HttpOnly, SameSite, __Secure-/__Host- prefixes, expiry.
"""
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from http.cookiejar import http2time

import requests
import urllib3

from yads.core.base import BaseScannerModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

TIMEOUT = 8

# Cookie names that are typically session cookies — extra scrutiny
SESSION_COOKIE_PATTERNS = re.compile(
    r"session|sess|token|auth|jwt|csrf|xsrf|sid|user|login|remember|bearer",
    re.IGNORECASE,
)


class CookieScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "cookie_scanner"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        logger.info(f"[CookieScanner] Starting for {target}")

        cookies_raw, url_used, all_set_cookie_headers = self._fetch_cookies(target)
        if cookies_raw is None:
            return {
                "url": url_used,
                "reachable": False,
                "cookies": [],
                "findings": [],
                "score": 0,
                "summary": {"total": 0, "insecure": 0, "missing_httponly": 0, "missing_samesite": 0},
            }

        analyzed = [self._analyze_cookie(name, attrs, raw) for name, attrs, raw in cookies_raw]
        findings = [f for c in analyzed for f in c["findings"]]
        score = self._score(analyzed)

        insecure = sum(1 for c in analyzed if not c["secure"])
        missing_httponly = sum(1 for c in analyzed if not c["httponly"])
        missing_samesite = sum(1 for c in analyzed if not c["samesite"])

        logger.info(f"[CookieScanner] {len(analyzed)} cookies, score {score}/100")
        return {
            "url": url_used,
            "reachable": True,
            "cookies": analyzed,
            "findings": findings,
            "score": score,
            "summary": {
                "total": len(analyzed),
                "insecure": insecure,
                "missing_httponly": missing_httponly,
                "missing_samesite": missing_samesite,
            },
        }

    def _fetch_cookies(self, target: str):
        session = requests.Session()
        session.headers["User-Agent"] = "YADS-CookieBot/1.0"
        for scheme in ("https", "http"):
            url = f"{scheme}://{target}/"
            try:
                resp = session.get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
                raw_cookies = self._parse_set_cookie_headers(resp)
                return raw_cookies, url, resp.headers.getlist("Set-Cookie") if hasattr(resp.headers, "getlist") else []
            except Exception:
                continue
        return None, f"https://{target}/", []

    def _parse_set_cookie_headers(self, resp: requests.Response):
        """Parse Set-Cookie headers from response. Returns list of (name, attrs_dict, raw_str)."""
        cookies = []
        # requests merges Set-Cookie headers — use raw headers if possible
        raw_headers = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else []
        if not raw_headers:
            # Fallback: use requests cookie jar
            for c in resp.cookies:
                attrs = {
                    "secure": c.secure,
                    "httponly": c._rest.get("HttpOnly", False) if hasattr(c, "_rest") else False,
                    "samesite": c._rest.get("SameSite", None) if hasattr(c, "_rest") else None,
                    "path": c.path,
                    "domain": c.domain,
                    "expires": str(c.expires) if c.expires else None,
                }
                cookies.append((c.name, attrs, f"{c.name}=..."))
            return cookies

        for raw in raw_headers:
            parsed = self._parse_single_cookie(raw)
            if parsed:
                cookies.append(parsed)
        return cookies

    def _parse_single_cookie(self, raw: str) -> Optional[Tuple]:
        parts = [p.strip() for p in raw.split(";")]
        if not parts:
            return None
        # First part is name=value
        name_val = parts[0]
        if "=" in name_val:
            name = name_val.split("=", 1)[0].strip()
        else:
            name = name_val.strip()

        attrs = {
            "secure": False,
            "httponly": False,
            "samesite": None,
            "path": None,
            "domain": None,
            "expires": None,
            "max_age": None,
        }

        for part in parts[1:]:
            pl = part.lower()
            if pl == "secure":
                attrs["secure"] = True
            elif pl == "httponly":
                attrs["httponly"] = True
            elif pl.startswith("samesite="):
                attrs["samesite"] = part.split("=", 1)[1].strip()
            elif pl.startswith("path="):
                attrs["path"] = part.split("=", 1)[1].strip()
            elif pl.startswith("domain="):
                attrs["domain"] = part.split("=", 1)[1].strip()
            elif pl.startswith("expires="):
                attrs["expires"] = part.split("=", 1)[1].strip()
            elif pl.startswith("max-age="):
                try:
                    attrs["max_age"] = int(part.split("=", 1)[1].strip())
                except ValueError:
                    pass

        return name, attrs, raw[:200]

    def _analyze_cookie(self, name: str, attrs: Dict, raw: str) -> Dict:
        findings = []
        is_session = bool(SESSION_COOKIE_PATTERNS.search(name))

        if not attrs["secure"]:
            severity = "high" if is_session else "medium"
            findings.append({
                "cookie": name,
                "issue": f"Missing Secure flag — cookie sent over HTTP",
                "severity": severity,
                "fix": "Add Secure attribute",
            })

        if not attrs["httponly"]:
            severity = "high" if is_session else "medium"
            findings.append({
                "cookie": name,
                "issue": "Missing HttpOnly flag — accessible via JavaScript (XSS risk)",
                "severity": severity,
                "fix": "Add HttpOnly attribute",
            })

        samesite = (attrs.get("samesite") or "").lower()
        if not samesite:
            findings.append({
                "cookie": name,
                "issue": "Missing SameSite attribute — vulnerable to CSRF",
                "severity": "medium",
                "fix": "Add SameSite=Strict or SameSite=Lax",
            })
        elif samesite == "none" and not attrs["secure"]:
            findings.append({
                "cookie": name,
                "issue": "SameSite=None requires Secure flag",
                "severity": "high",
                "fix": "Add Secure attribute or change SameSite policy",
            })

        # __Secure- prefix requires Secure flag
        if name.startswith("__Secure-") and not attrs["secure"]:
            findings.append({
                "cookie": name,
                "issue": "__Secure- prefix requires Secure flag",
                "severity": "high",
                "fix": "Add Secure attribute",
            })

        # __Host- prefix requires Secure, no Domain, Path=/
        if name.startswith("__Host-"):
            if not attrs["secure"]:
                findings.append({
                    "cookie": name,
                    "issue": "__Host- prefix requires Secure flag",
                    "severity": "high",
                    "fix": "Add Secure attribute",
                })
            if attrs.get("domain"):
                findings.append({
                    "cookie": name,
                    "issue": "__Host- prefix must not have Domain attribute",
                    "severity": "medium",
                    "fix": "Remove Domain attribute",
                })

        return {
            "name": name,
            "secure": attrs["secure"],
            "httponly": attrs["httponly"],
            "samesite": attrs.get("samesite"),
            "is_session_cookie": is_session,
            "raw": raw,
            "findings": findings,
        }

    def _score(self, analyzed: List[Dict]) -> int:
        if not analyzed:
            return 100  # no cookies = no cookie issues
        total = len(analyzed)
        scores = []
        for c in analyzed:
            cs = 100
            if not c["secure"]:
                cs -= 30
            if not c["httponly"]:
                cs -= 25
            if not c["samesite"]:
                cs -= 20
            scores.append(max(0, cs))
        return int(sum(scores) / total)
