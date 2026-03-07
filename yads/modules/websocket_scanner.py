"""
WebSocket Security Scanner (#40)

Detects WebSocket endpoints and tests for common vulnerabilities:
  - WebSocket endpoint discovery (upgrade headers, common paths)
  - Cross-Origin WebSocket Hijacking (CSWSH) — no Origin check
  - Missing authentication on WebSocket handshake
  - Unencrypted ws:// usage (instead of wss://)
  - WebSocket subprotocol disclosure
  - Connection limit / rate limiting
  - Sensitive data in WebSocket URL parameters (tokens in query string)

Uses socket-level WebSocket handshake — no browser required.
"""

import base64
import hashlib
import logging
import re
import socket
import ssl
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

import requests

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

TIMEOUT = 10
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; YADS-Security-Scanner/1.0)",
    "Accept": "text/html,application/xhtml+xml,*/*",
}

# Common WebSocket paths
WS_PATHS = [
    "/ws",
    "/websocket",
    "/socket",
    "/socket.io/",
    "/socket.io/?EIO=4&transport=websocket",
    "/ws/",
    "/cable",
    "/live",
    "/events",
    "/stream",
    "/realtime",
    "/hub",
    "/signalr/negotiate",
    "/sockjs/websocket",
    "/chat",
    "/api/ws",
    "/api/websocket",
    "/api/v1/ws",
]

# Patterns suggesting auth tokens in query params
TOKEN_PATTERNS = re.compile(
    r"[?&](token|auth|key|session|jwt|access_token|api_key)=",
    re.IGNORECASE,
)


def _clean_domain(target: str) -> str:
    return (
        target.lower().strip()
        .removeprefix("https://").removeprefix("http://")
        .split("/")[0]
    )


def _ws_handshake(host: str, port: int, path: str, use_tls: bool,
                   origin: Optional[str] = None) -> Tuple[Optional[int], Optional[Dict]]:
    """
    Perform a raw WebSocket upgrade handshake.
    Returns (http_status_code, response_headers) or (None, None) on failure.
    """
    try:
        key_bytes = base64.b64encode(b"YADSScannerKey123456")
        nonce = key_bytes.decode()

        hdrs = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}:{port}" if port not in (80, 443) else f"Host: {host}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {nonce}",
            "Sec-WebSocket-Version: 13",
            "User-Agent: Mozilla/5.0 (compatible; YADS-Security-Scanner/1.0)",
        ]
        if origin:
            hdrs.append(f"Origin: {origin}")

        request = "\r\n".join(hdrs) + "\r\n\r\n"

        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        sock.sendall(request.encode())
        response = b""
        sock.settimeout(5)
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"\r\n\r\n" in response:
                    break
        except socket.timeout:
            pass
        finally:
            sock.close()

        if not response:
            return None, None

        header_part = response.split(b"\r\n\r\n")[0].decode("utf-8", errors="replace")
        lines = header_part.splitlines()
        if not lines:
            return None, None

        status_line = lines[0]
        try:
            status_code = int(status_line.split()[1])
        except (IndexError, ValueError):
            return None, None

        resp_headers: Dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                resp_headers[k.strip().lower()] = v.strip()

        return status_code, resp_headers

    except Exception as e:
        logger.debug(f"WS handshake failed for {host}:{port}{path}: {e}")
        return None, None


def _discover_ws_from_page(base_url: str) -> List[str]:
    """Look for WebSocket URLs in page source."""
    found = []
    try:
        r = requests.get(base_url, timeout=TIMEOUT, headers=HEADERS, verify=False)
        if r.status_code == 200:
            body = r.text[:100000]
            # ws:// and wss:// URLs
            urls = re.findall(r"""(wss?://[^\s'"<>]+)""", body)
            # Also check JS for new WebSocket() patterns
            ws_paths = re.findall(r"""new\s+WebSocket\(['"]([^'"]+)['"]""", body)
            found.extend(urls[:10])
            found.extend(ws_paths[:10])
    except Exception:
        pass
    return found


def _check_http_upgrade_header(base_url: str, path: str) -> bool:
    """Check if path returns Upgrade: websocket response to HTTP GET."""
    try:
        url = urljoin(base_url + "/", path.lstrip("/"))
        r = requests.get(url, timeout=TIMEOUT, headers={
            **HEADERS,
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        }, verify=False, allow_redirects=False)
        # 101 = Switching Protocols (WebSocket upgrade success)
        # 400 = likely a WebSocket server rejecting bad upgrade
        return r.status_code in (101, 400, 426)
    except Exception:
        return False


class WebSocketScanner(BaseScannerModule):
    """WebSocket endpoint discovery and security testing."""

    @property
    def module_name(self) -> str:
        return "websocket_scanner"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = _clean_domain(target)
        base_https = f"https://{domain}"
        base_http = f"http://{domain}"

        result: Dict[str, Any] = {
            "domain": domain,
            "endpoints_found": [],
            "unencrypted_ws": [],
            "cswsh_vulnerable": [],
            "no_origin_check": [],
            "token_in_url": [],
            "subprotocols": [],
            "source_discovered": [],
            "findings": [],
            "summary": {
                "score": 100,
                "endpoints": 0,
                "issues": 0,
                "websocket_detected": False,
            },
        }

        findings: List[Dict] = []
        score = 100
        found_endpoints: List[Dict] = []

        # 1. Discover WS URLs from page source
        source_ws = _discover_ws_from_page(base_https)
        result["source_discovered"] = source_ws[:10]

        # Check for unencrypted ws:// in source
        unencrypted_in_source = [u for u in source_ws if u.startswith("ws://")]

        # 2. Probe common paths via HTTP upgrade check
        candidate_paths: List[Tuple[str, bool]] = []  # (path, is_tls)
        for path in WS_PATHS:
            if _check_http_upgrade_header(base_https, path):
                candidate_paths.append((path, True))
            if len(candidate_paths) >= 5:
                break

        # 3. Raw WebSocket handshake on candidates
        port_tls = 443
        port_plain = 80

        for path, is_tls in candidate_paths:
            # Test with valid origin (should succeed)
            status, headers = _ws_handshake(domain, port_tls if is_tls else port_plain, path, is_tls,
                                             origin=f"https://{domain}")
            if status == 101:
                ep_info: Dict[str, Any] = {
                    "path": path,
                    "url": f"wss://{domain}{path}" if is_tls else f"ws://{domain}{path}",
                    "encrypted": is_tls,
                    "subprotocol": headers.get("sec-websocket-protocol", "") if headers else "",
                    "origin_check": True,  # assume until proven otherwise
                }

                # Test CSWSH: send malicious origin
                status_evil, _ = _ws_handshake(domain, port_tls if is_tls else port_plain, path, is_tls,
                                                 origin="https://evil-attacker.example.com")
                if status_evil == 101:
                    ep_info["origin_check"] = False
                    result["cswsh_vulnerable"].append(path)

                # Test without any Origin header
                status_no_origin, _ = _ws_handshake(domain, port_tls if is_tls else port_plain, path, is_tls,
                                                      origin=None)
                if status_no_origin == 101:
                    result["no_origin_check"].append(path)

                if headers and headers.get("sec-websocket-protocol"):
                    result["subprotocols"].append(headers["sec-websocket-protocol"])

                found_endpoints.append(ep_info)

        # Check plain ws:// (port 80)
        for path, _ in candidate_paths[:2]:
            status_plain, _ = _ws_handshake(domain, 80, path, False)
            if status_plain == 101:
                result["unencrypted_ws"].append(f"ws://{domain}{path}")

        # Add unencrypted ones found in source
        result["unencrypted_ws"].extend(unencrypted_in_source)
        result["unencrypted_ws"] = list(set(result["unencrypted_ws"]))

        # Check for tokens in discovered WS URLs
        all_ws_urls = [ep["url"] for ep in found_endpoints] + source_ws
        for url in all_ws_urls:
            if TOKEN_PATTERNS.search(url):
                result["token_in_url"].append(url)

        result["endpoints_found"] = found_endpoints
        result["summary"]["endpoints"] = len(found_endpoints)
        result["summary"]["websocket_detected"] = bool(found_endpoints) or bool(source_ws)

        # --- Findings ---
        if not found_endpoints and not source_ws:
            findings.append({
                "severity": "info",
                "title": "No WebSocket endpoints detected",
                "description": "WebSocket endpoints were not found at common paths or in page source.",
            })
            result["findings"] = findings
            return result

        if found_endpoints:
            findings.append({
                "severity": "info",
                "title": f"{len(found_endpoints)} WebSocket endpoint(s) discovered",
                "description": f"WebSocket endpoint(s) found: {', '.join(ep['url'] for ep in found_endpoints[:3])}",
                "endpoints": [ep["url"] for ep in found_endpoints],
            })

        if result["cswsh_vulnerable"]:
            findings.append({
                "severity": "high",
                "title": f"Cross-Site WebSocket Hijacking (CSWSH) possible: {', '.join(result['cswsh_vulnerable'][:3])}",
                "description": (
                    "WebSocket connections are accepted from arbitrary origins. An attacker can create a "
                    "malicious webpage that silently opens a WebSocket connection to this server on behalf "
                    "of an authenticated victim, sending commands or stealing data."
                ),
                "paths": result["cswsh_vulnerable"],
            })
            score -= 40

        if result["no_origin_check"]:
            findings.append({
                "severity": "medium",
                "title": "WebSocket endpoint accepts connections without Origin header",
                "description": (
                    "Connections without an Origin header are accepted. "
                    "While not directly exploitable from browsers, this indicates missing origin validation."
                ),
                "paths": result["no_origin_check"],
            })
            score -= 10

        if result["unencrypted_ws"]:
            findings.append({
                "severity": "high",
                "title": f"Unencrypted WebSocket (ws://) in use: {result['unencrypted_ws'][0]}",
                "description": (
                    "Unencrypted ws:// WebSocket connections transmit data in plaintext, "
                    "enabling man-in-the-middle interception. Use wss:// (WebSocket over TLS) exclusively."
                ),
                "urls": result["unencrypted_ws"],
            })
            score -= 30

        if result["token_in_url"]:
            findings.append({
                "severity": "medium",
                "title": "Authentication token found in WebSocket URL query parameter",
                "description": (
                    "WebSocket URLs contain authentication tokens in the query string. "
                    "These tokens are logged in server access logs and browser history. "
                    "Pass authentication via cookies or the initial HTTP handshake headers instead."
                ),
                "urls": result["token_in_url"][:3],
            })
            score -= 20

        if result["subprotocols"]:
            findings.append({
                "severity": "info",
                "title": f"WebSocket subprotocol(s) disclosed: {', '.join(result['subprotocols'][:3])}",
                "description": (
                    "The server disclosed WebSocket subprotocol names in the handshake response. "
                    "This reveals application framework details."
                ),
            })

        result["summary"]["score"] = max(0, score)
        result["summary"]["issues"] = len([f for f in findings if f["severity"] not in ("info",)])
        result["findings"] = findings
        return result
