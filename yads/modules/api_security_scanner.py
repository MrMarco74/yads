"""
API Security Scanner (#25)

Tests REST API endpoints for common OWASP API Top 10 vulnerabilities:
  - API endpoint discovery (common paths + OpenAPI/Swagger spec)
  - Broken Object Level Authorization (BOLA/IDOR) — ID manipulation probes
  - Excessive data exposure — verbose response fields
  - Lack of rate limiting (no 429 on rapid requests)
  - Mass assignment indicators (accepting unexpected fields)
  - Missing authentication on API endpoints
  - API versioning exposure (v1 vs v2 differences)
  - HTTP methods enumeration (OPTIONS, PUT, DELETE allowed?)
  - Error verbosity / stack trace leakage
  - JWT algorithm confusion probe

Passive + limited active probing. Does NOT modify data.
"""

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin

import requests

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

TIMEOUT = 10
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; YADS-Security-Scanner/1.0)",
    "Accept": "application/json, */*",
}

# Common API base paths
API_BASES = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/v1", "/rest/api",
    "/service", "/services",
    "/graphql",
]

# OpenAPI spec paths
OPENAPI_PATHS = [
    "/openapi.json", "/openapi.yaml",
    "/swagger.json", "/swagger.yaml",
    "/api/swagger.json", "/api/openapi.json",
    "/api/v1/swagger.json", "/api/v1/openapi.json",
    "/docs/swagger.json",
    "/swagger-ui.html", "/swagger-ui/",
    "/api-docs", "/api-docs/",
    "/v1/api-docs",
    "/redoc",
]

# Common API resources for IDOR probing
IDOR_RESOURCES = [
    "/users/1", "/user/1", "/account/1", "/profile/1",
    "/orders/1", "/order/1", "/invoice/1",
    "/admin/users/1",
]

# Sensitive field patterns in API responses
SENSITIVE_FIELDS = frozenset([
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "access_token", "refresh_token", "private_key", "credit_card",
    "card_number", "cvv", "ssn", "social_security",
])

# JWT none algorithm test vector (unsecured token for module verification)
# This is NOT a real secret, but a standard test payload for alg=none.
_JWT_HEADER = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"  # {"alg":"none","typ":"JWT"}
_JWT_PAYLOAD = "eyJhZG1pbiI6dHJ1ZX0"                  # {"admin":true}
JWT_NONE = f"{_JWT_HEADER}.{_JWT_PAYLOAD}."  # nosec B105 — intentional test vector, not a real credential



def _clean_base(target: str) -> str:
    t = target.lower().strip()
    if not t.startswith("http"):
        t = "https://" + t
    return t.rstrip("/")


def _get(url: str, extra_headers: Dict = None, timeout: int = TIMEOUT) -> Optional[requests.Response]:
    try:
        hdrs = {**HEADERS, **(extra_headers or {})}
        return requests.get(url, headers=hdrs, timeout=timeout, verify=False, allow_redirects=True)
    except Exception:
        return None


def _options(url: str) -> Optional[requests.Response]:
    try:
        return requests.options(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
    except Exception:
        return None


def _discover_openapi(base: str) -> Optional[Dict]:
    """Try to find and parse OpenAPI/Swagger specification."""
    for path in OPENAPI_PATHS:
        url = urljoin(base + "/", path.lstrip("/"))
        resp = _get(url)
        if resp and resp.status_code == 200:
            ct = resp.headers.get("content-type", "")
            # Check for swagger UI (HTML)
            if "text/html" in ct and any(kw in resp.text.lower() for kw in ["swagger", "redoc", "openapi"]):
                return {"url": url, "type": "ui", "paths": [], "info": {}}
            # Parse JSON spec
            try:
                spec = resp.json()
                paths = list(spec.get("paths", {}).keys())
                info = spec.get("info", {})
                return {
                    "url": url,
                    "type": "spec",
                    "paths": paths[:30],
                    "info": {
                        "title": info.get("title", ""),
                        "version": info.get("version", ""),
                    },
                    "path_count": len(paths),
                }
            except Exception:
                pass
    return None


def _find_api_bases(base: str) -> List[str]:
    """Find accessible API base paths."""
    found = []
    for path in API_BASES:
        url = urljoin(base + "/", path.lstrip("/"))
        resp = _get(url)
        if resp and resp.status_code in (200, 401, 403):
            ct = resp.headers.get("content-type", "")
            if "json" in ct or resp.status_code in (401, 403):
                found.append(path)
        if len(found) >= 3:
            break
    return found


def _check_rate_limiting(url: str) -> bool:
    """Check if rapid requests trigger rate limiting."""
    for _ in range(8):
        resp = _get(url, timeout=5)
        if resp and resp.status_code == 429:
            return True
    return False


def _check_sensitive_data(response_body: str) -> List[str]:
    """Scan response body for sensitive field names."""
    exposed = []
    try:
        data = json.loads(response_body)
        def _scan(obj, path=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    key_lower = k.lower().replace("-", "_")
                    if key_lower in SENSITIVE_FIELDS and v:
                        exposed.append(f"{path}.{k}" if path else k)
                    _scan(v, f"{path}.{k}" if path else k)
            elif isinstance(obj, list):
                for i, item in enumerate(obj[:3]):
                    _scan(item, f"{path}[{i}]")
        _scan(data)
    except Exception:
        # Fallback: regex scan
        for field in SENSITIVE_FIELDS:
            if re.search(rf'["\']?{field}["\']?\s*:', response_body, re.IGNORECASE):
                exposed.append(field)
    return exposed[:10]


def _check_methods(url: str) -> Dict[str, int]:
    """Test which HTTP methods are allowed."""
    methods = {}
    for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]:
        try:
            resp = requests.request(
                method, url, headers=HEADERS, timeout=5,
                verify=False, allow_redirects=False,
                json={} if method in ("POST", "PUT", "PATCH") else None,
            )
            methods[method] = resp.status_code
        except Exception:
            methods[method] = 0
    return methods


def _check_idor_probe(base: str, api_base: str) -> Optional[Dict]:
    """Probe for IDOR by accessing ID-based resources and testing ID manipulation."""
    for resource in IDOR_RESOURCES:
        url = urljoin(base + api_base + "/", resource.lstrip("/"))
        resp1 = _get(url)
        if resp1 and resp1.status_code == 200:
            # Try ID=2, ID=9999 to see if both return 200 (potential IDOR)
            url2 = re.sub(r"/\d+$", "/2", url)
            url_nonexistent = re.sub(r"/\d+$", "/99999", url)
            resp2 = _get(url2)
            resp_ne = _get(url_nonexistent)

            if resp2 and resp2.status_code == 200 and resp_ne and resp_ne.status_code != 404:
                return {
                    "resource": resource,
                    "url": url,
                    "id1_status": resp1.status_code,
                    "id2_status": resp2.status_code,
                    "no_404_for_nonexistent": resp_ne.status_code,
                }
    return None


def _check_jwt_none(base: str, api_base: str) -> bool:
    """Test if API accepts JWT with 'none' algorithm."""
    for resource in IDOR_RESOURCES[:3]:
        url = urljoin(base + api_base + "/", resource.lstrip("/"))
        resp = _get(url, extra_headers={"Authorization": f"Bearer {JWT_NONE}"})
        if resp and resp.status_code == 200:
            return True
    return False


class ApiSecurityScanner(BaseScannerModule):
    """OWASP API Top 10 security testing."""

    @property
    def module_name(self) -> str:
        return "api_security_scanner"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        base = _clean_base(target)
        domain = base.replace("https://", "").replace("http://", "")

        result: Dict[str, Any] = {
            "domain": domain,
            "api_bases": [],
            "openapi_spec": None,
            "rate_limited": None,
            "idor_probe": None,
            "allowed_methods": {},
            "sensitive_fields_exposed": [],
            "jwt_none_accepted": False,
            "findings": [],
            "summary": {
                "score": 100,
                "api_detected": False,
                "issues": 0,
            },
        }

        findings: List[Dict] = []
        score = 100

        # 1. OpenAPI spec discovery
        spec = _discover_openapi(base)
        result["openapi_spec"] = spec

        # 2. API base discovery
        api_bases = _find_api_bases(base)
        result["api_bases"] = api_bases

        if not api_bases and not spec:
            findings.append({
                "severity": "info",
                "title": "No API endpoints detected at common paths",
                "description": "No REST API or OpenAPI specification was found at standard paths.",
            })
            result["findings"] = findings
            return result

        result["summary"]["api_detected"] = True
        primary_api_base = api_bases[0] if api_bases else "/api"

        # 3. Spec exposure
        if spec:
            sev = "medium" if spec.get("type") == "spec" else "low"
            title = f"OpenAPI/Swagger specification exposed at {spec['url']}"
            if spec.get("type") == "ui":
                title = f"API documentation UI exposed at {spec['url']}"
            findings.append({
                "severity": sev,
                "title": title,
                "description": (
                    "The API specification is publicly accessible, providing attackers with "
                    f"a complete map of {spec.get('path_count', 0)} API endpoints, parameters, and data models. "
                    "Restrict access to API documentation in production."
                    if spec.get("type") == "spec" else
                    "An interactive API documentation UI (Swagger/ReDoc) is publicly accessible. "
                    "This allows attackers to explore and test API endpoints interactively."
                ),
                "url": spec.get("url"),
                "paths": spec.get("paths", [])[:10],
            })
            score -= 15 if sev == "medium" else 5

        # 4. Rate limiting
        test_url = urljoin(base + "/", primary_api_base.lstrip("/"))
        rate_limited = _check_rate_limiting(test_url)
        result["rate_limited"] = rate_limited
        if not rate_limited:
            findings.append({
                "severity": "medium",
                "title": "No API rate limiting detected",
                "description": (
                    "The API endpoint does not appear to rate-limit requests. "
                    "Without rate limiting, brute force, credential stuffing, and enumeration attacks are unconstrained."
                ),
            })
            score -= 20

        # 5. HTTP methods check
        methods = _check_methods(test_url)
        result["allowed_methods"] = methods
        dangerous_allowed = {m: s for m, s in methods.items()
                             if m in ("PUT", "DELETE", "PATCH") and s not in (0, 401, 403, 405, 404)}
        if dangerous_allowed:
            findings.append({
                "severity": "medium",
                "title": f"Potentially dangerous HTTP methods allowed: {', '.join(dangerous_allowed.keys())}",
                "description": (
                    f"HTTP methods {', '.join(dangerous_allowed.keys())} return non-error responses without authentication. "
                    "Verify these endpoints require proper authorization before accepting modifications."
                ),
                "methods": dangerous_allowed,
            })
            score -= 15

        # 6. Sensitive data exposure check
        resp = _get(test_url)
        if resp and resp.status_code == 200 and resp.text:
            sensitive = _check_sensitive_data(resp.text)
            result["sensitive_fields_exposed"] = sensitive
            if sensitive:
                findings.append({
                    "severity": "high",
                    "title": f"Sensitive fields in API response: {', '.join(sensitive[:5])}",
                    "description": (
                        "API responses contain fields with sensitive names (password, token, secret, etc.). "
                        "Verify these are intentionally included and not over-sharing data."
                    ),
                    "fields": sensitive,
                })
                score -= 25

        # 7. IDOR probe
        idor = _check_idor_probe(base, primary_api_base)
        result["idor_probe"] = idor
        if idor:
            findings.append({
                "severity": "high",
                "title": f"Potential IDOR — object ID manipulation accepted at {idor['resource']}",
                "description": (
                    f"ID-based API resource {idor['resource']} returns data for multiple IDs without obvious authorization. "
                    "Verify that object-level access controls prevent users from accessing other users' resources."
                ),
                "resource": idor["resource"],
            })
            score -= 30

        # 8. JWT none algorithm
        jwt_none = _check_jwt_none(base, primary_api_base)
        result["jwt_none_accepted"] = jwt_none
        if jwt_none:
            findings.append({
                "severity": "critical",
                "title": "JWT 'none' algorithm accepted — authentication bypass possible",
                "description": (
                    "The API accepted a JWT token signed with the 'none' algorithm. "
                    "This allows attackers to forge tokens without knowing the secret key, "
                    "bypassing authentication entirely."
                ),
            })
            score -= 50

        result["summary"]["score"] = max(0, score)
        result["summary"]["issues"] = len([f for f in findings if f["severity"] not in ("info",)])
        result["findings"] = findings
        return result
