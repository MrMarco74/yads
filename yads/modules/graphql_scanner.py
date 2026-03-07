"""
GraphQL Security Scanner (#39)

Detects GraphQL endpoints and tests for common misconfigurations:
  - GraphQL endpoint discovery (common paths)
  - Introspection enabled (exposes full schema)
  - Query depth limit (DoS via deeply nested queries)
  - Query complexity limit
  - Batch query support (brute force amplification)
  - Field suggestions enabled (information leakage)
  - GraphQL Playground / GraphiQL exposed (dev tools in prod)
  - Error verbosity (stack traces, internal paths)
  - CSRF protection on GraphQL endpoint

No authentication required — all passive/unauthenticated probing.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin

import requests

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

TIMEOUT = 12
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; YADS-Security-Scanner/1.0)",
    "Content-Type": "application/json",
    "Accept": "application/json, text/html, */*",
}

GRAPHQL_PATHS = [
    "/graphql",
    "/graphql/",
    "/api/graphql",
    "/api/v1/graphql",
    "/api/v2/graphql",
    "/query",
    "/gql",
    "/graph",
    "/v1/graphql",
    "/v2/graphql",
    "/data",
    "/graphql-explorer",
    "/_graphql",
    "/hasura/v1/graphql",
    "/v1/query",
]

INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      kind
      fields {
        name
      }
    }
  }
}
"""

DEPTH_BOMB_QUERY = """
{
  a { a { a { a { a { a { a { a { a { a { __typename } } } } } } } } } }
}
"""

BATCH_QUERY = json.dumps([
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
])

SIMPLE_QUERY = json.dumps({"query": "{ __typename }"})


def _clean_base(target: str) -> str:
    t = target.lower().strip()
    if not t.startswith("http"):
        t = "https://" + t
    return t.rstrip("/")


def _post(url: str, data: str, extra_headers: Dict = None) -> Optional[requests.Response]:
    try:
        hdrs = {**HEADERS, **(extra_headers or {})}
        r = requests.post(url, data=data, headers=hdrs, timeout=TIMEOUT, verify=False)
        return r
    except Exception:
        return None


def _get(url: str) -> Optional[requests.Response]:
    try:
        return requests.get(url, headers={k: v for k, v in HEADERS.items() if k != "Content-Type"},
                            timeout=TIMEOUT, verify=False, allow_redirects=True)
    except Exception:
        return None


def _is_graphql_response(resp: requests.Response) -> bool:
    """Check if response looks like GraphQL."""
    try:
        data = resp.json()
        return "data" in data or "errors" in data
    except Exception:
        return False


def _check_playground(resp: requests.Response) -> bool:
    """Check if response is a GraphQL playground/GraphiQL UI."""
    if resp.status_code != 200:
        return False
    ct = resp.headers.get("content-type", "")
    if "text/html" in ct:
        body = resp.text[:5000].lower()
        return any(kw in body for kw in ["graphiql", "graphql playground", "apollo studio", "graphql explorer"])
    return False


def _check_introspection(url: str) -> Optional[Dict]:
    """Test if introspection is enabled."""
    payload = json.dumps({"query": INTROSPECTION_QUERY})
    resp = _post(url, payload)
    if resp is None:
        return None
    try:
        if resp.status_code == 200:
            data = resp.json()
            if "data" in data and "__schema" in (data.get("data") or {}):
                schema = data["data"]["__schema"]
                types = schema.get("types", [])
                user_types = [t["name"] for t in types if not t["name"].startswith("__")]
                return {
                    "enabled": True,
                    "type_count": len(user_types),
                    "types": user_types[:30],
                }
            if "errors" in data:
                # Check if introspection is disabled
                for err in data.get("errors", []):
                    msg = (err.get("message") or "").lower()
                    if "introspection" in msg:
                        return {"enabled": False, "disabled_message": err.get("message", "")}
    except Exception:
        pass
    return None


def _check_depth_limit(url: str) -> Optional[bool]:
    """Test if deeply nested queries are rejected."""
    payload = json.dumps({"query": DEPTH_BOMB_QUERY})
    resp = _post(url, payload)
    if resp is None:
        return None
    try:
        if resp.status_code in (200, 400):
            data = resp.json()
            errors = data.get("errors", [])
            for err in errors:
                msg = (err.get("message") or "").lower()
                if any(k in msg for k in ["depth", "complexity", "limit", "exceeded"]):
                    return True  # Depth limiting active
            if data.get("data"):
                return False  # Query succeeded — no depth limit
    except Exception:
        pass
    return None


def _check_batch(url: str) -> bool:
    """Test if batch queries are supported."""
    resp = _post(url, BATCH_QUERY)
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            if isinstance(data, list) and len(data) == 3:
                return True
        except Exception:
            pass
    return False


def _check_field_suggestions(url: str) -> bool:
    """Test if field suggestion errors leak schema info."""
    # Query a non-existent field — GraphQL servers may suggest similar fields
    payload = json.dumps({"query": "{ nonExistentFieldXYZ }"})
    resp = _post(url, payload)
    if resp:
        try:
            data = resp.json()
            for err in data.get("errors", []):
                msg = (err.get("message") or "").lower()
                if "did you mean" in msg or "suggestion" in msg:
                    return True
        except Exception:
            pass
    return False


def _check_csrf(url: str) -> bool:
    """Test if GraphQL endpoint accepts requests without CSRF token (form content-type)."""
    try:
        r = requests.post(
            url,
            data={"query": "{ __typename }"},
            headers={
                "User-Agent": HEADERS["User-Agent"],
                "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout=TIMEOUT,
            verify=False,
        )
        if r.status_code == 200:
            try:
                data = r.json()
                return "data" in data or "errors" in data
            except Exception:
                pass
    except Exception:
        pass
    return False


def _check_verbose_errors(url: str) -> Optional[str]:
    """Check if errors reveal stack traces or internal paths."""
    payload = json.dumps({"query": "{ __YADS_PROBE_ERROR }"})
    resp = _post(url, payload)
    if resp:
        try:
            text = resp.text
            patterns = [
                r"at [A-Z][a-zA-Z]+\.",      # Java/JS stack trace
                r"File \"[/\\]",              # Python traceback
                r"Traceback \(most recent",   # Python
                r"/home/", r"/var/", r"/usr/",  # Unix paths
                r"node_modules",
                r"\\Program Files\\",          # Windows
            ]
            for pattern in patterns:
                if re.search(pattern, text):
                    return re.search(pattern, text).group(0)
        except Exception:
            pass
    return None


class GraphQlScanner(BaseScannerModule):
    """GraphQL endpoint discovery and security misconfiguration detection."""

    @property
    def module_name(self) -> str:
        return "graphql_scanner"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        base = _clean_base(target)
        domain = base.replace("https://", "").replace("http://", "")

        result: Dict[str, Any] = {
            "domain": domain,
            "endpoints_found": [],
            "introspection": None,
            "playground_exposed": False,
            "batch_queries": False,
            "depth_limited": None,
            "field_suggestions": False,
            "csrf_vulnerable": False,
            "verbose_errors": None,
            "schema_types": [],
            "findings": [],
            "summary": {
                "score": 100,
                "endpoints": 0,
                "issues": 0,
                "graphql_detected": False,
            },
        }

        findings: List[Dict] = []
        score = 100
        graphql_endpoints: List[str] = []

        # Discovery phase
        for path in GRAPHQL_PATHS:
            url = urljoin(base + "/", path.lstrip("/"))

            # Check GET first (playground detection)
            get_resp = _get(url)
            if get_resp:
                if _check_playground(get_resp):
                    if url not in graphql_endpoints:
                        graphql_endpoints.append(url)
                    result["playground_exposed"] = True

            # POST with simple query
            post_resp = _post(url, SIMPLE_QUERY)
            if post_resp and _is_graphql_response(post_resp):
                if url not in graphql_endpoints:
                    graphql_endpoints.append(url)

            if len(graphql_endpoints) >= 3:
                break  # Found enough

        result["endpoints_found"] = graphql_endpoints
        result["summary"]["endpoints"] = len(graphql_endpoints)
        result["summary"]["graphql_detected"] = bool(graphql_endpoints)

        if not graphql_endpoints:
            findings.append({
                "severity": "info",
                "title": "No GraphQL endpoints detected",
                "description": "GraphQL was not found at common paths. The application may not use GraphQL.",
            })
            result["findings"] = findings
            return result

        # Use first found endpoint for security tests
        gql_url = graphql_endpoints[0]

        # Introspection
        intro = _check_introspection(gql_url)
        result["introspection"] = intro
        if intro and intro.get("enabled"):
            result["schema_types"] = intro.get("types", [])
            findings.append({
                "severity": "medium",
                "title": "GraphQL introspection enabled",
                "description": (
                    f"GraphQL introspection is enabled, exposing the full schema with {intro.get('type_count', 0)} types. "
                    "Attackers can enumerate all queries, mutations, and types to plan targeted attacks. "
                    "Disable introspection in production environments."
                ),
                "type_count": intro.get("type_count", 0),
                "types_sample": intro.get("types", [])[:10],
            })
            score -= 20

        # Playground / GraphiQL
        if result["playground_exposed"]:
            findings.append({
                "severity": "medium",
                "title": "GraphQL Playground / GraphiQL exposed in production",
                "description": (
                    "An interactive GraphQL IDE (Playground or GraphiQL) is publicly accessible. "
                    "This allows unauthenticated exploration of the API schema and query execution. "
                    "Disable dev tooling in production."
                ),
            })
            score -= 15

        # Batch queries
        batch = _check_batch(gql_url)
        result["batch_queries"] = batch
        if batch:
            findings.append({
                "severity": "low",
                "title": "GraphQL batch queries supported",
                "description": (
                    "The endpoint accepts batched query arrays. This can amplify brute force attacks "
                    "and rate limiting bypass — thousands of operations can be sent in a single request."
                ),
            })
            score -= 10

        # Depth limiting
        depth_limited = _check_depth_limit(gql_url)
        result["depth_limited"] = depth_limited
        if depth_limited is False:
            findings.append({
                "severity": "medium",
                "title": "No query depth limit detected",
                "description": (
                    "Deeply nested GraphQL queries were accepted without rejection. "
                    "This enables DoS attacks via 'query bombs' that exponentially increase server load."
                ),
            })
            score -= 15

        # Field suggestions
        suggestions = _check_field_suggestions(gql_url)
        result["field_suggestions"] = suggestions
        if suggestions:
            findings.append({
                "severity": "low",
                "title": "Field suggestion errors leak schema information",
                "description": (
                    "Error messages include 'Did you mean...?' suggestions, revealing valid field names "
                    "even without introspection enabled. Disable field suggestions in production."
                ),
            })
            score -= 5

        # CSRF
        csrf_vuln = _check_csrf(gql_url)
        result["csrf_vulnerable"] = csrf_vuln
        if csrf_vuln:
            findings.append({
                "severity": "medium",
                "title": "GraphQL endpoint accepts form-urlencoded requests (CSRF risk)",
                "description": (
                    "The GraphQL endpoint accepts application/x-www-form-urlencoded content type, "
                    "making it vulnerable to CSRF attacks from malicious websites. "
                    "Require Content-Type: application/json only."
                ),
            })
            score -= 15

        # Verbose errors
        verbose_path = _check_verbose_errors(gql_url)
        result["verbose_errors"] = verbose_path
        if verbose_path:
            findings.append({
                "severity": "low",
                "title": "Verbose error messages leak internal information",
                "description": (
                    f"Error responses contain internal details (e.g., '{verbose_path}'). "
                    "Stack traces and file paths help attackers understand the server environment."
                ),
                "sample": verbose_path,
            })
            score -= 10

        result["summary"]["score"] = max(0, score)
        result["summary"]["issues"] = len([f for f in findings if f["severity"] not in ("info",)])
        result["findings"] = findings
        return result
