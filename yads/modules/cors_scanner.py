"""
CORS Misconfiguration Scanner (Task #8)
=========================================
Tests Cross-Origin Resource Sharing policy by sending
crafted Origin headers and inspecting ACAO responses.
"""
import logging
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3

from yads.core.base import BaseScannerModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

TIMEOUT = 7

# Test origins — cover common misconfiguration patterns
TEST_ORIGINS = [
    ("evil.com", "arbitrary origin reflection"),
    ("evil.{target}", "subdomain wildcard reflection"),
    ("null", "null origin"),
    ("{target}.evil.com", "suffix bypass"),
]

CORS_RESPONSE_HEADERS = [
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "Access-Control-Expose-Headers",
]


class CORSScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "cors_scanner"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        logger.info(f"[CORS] Starting for {target}")

        findings = []
        tested_endpoints = []

        # Build test list
        test_cases = [
            (origin_template.replace("{target}", target), label)
            for origin_template, label in TEST_ORIGINS
        ]

        for scheme in ("https", "http"):
            url = f"{scheme}://{target}/"
            try:
                for origin, label in test_cases:
                    result = self._test_origin(url, origin, label, target)
                    tested_endpoints.append(result)
                    if result["vulnerable"]:
                        findings.append(result["finding"])
                break  # Only test whichever scheme works first
            except requests.exceptions.ConnectionError:
                continue

        score = 100 if not findings else max(0, 100 - len(findings) * 25)
        logger.info(f"[CORS] Done for {target} — {len(findings)} issues, score {score}")

        return {
            "target": target,
            "tested_endpoints": tested_endpoints,
            "findings": findings,
            "score": score,
        }

    def _test_origin(self, url: str, origin: str, label: str, target: str) -> Dict:
        try:
            resp = requests.options(
                url,
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET",
                },
                timeout=TIMEOUT,
                verify=False,
                allow_redirects=False,
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            vulnerable = False
            severity = "info"
            issue = None

            if acao == "*" and acac == "true":
                vulnerable = True
                severity = "critical"
                issue = "Wildcard ACAO (*) combined with Allow-Credentials: true — credentials cannot be sent with wildcard but misconfigured server"
            elif acao == origin and origin == "null":
                vulnerable = True
                severity = "high"
                issue = "Null origin is reflected — iframes and local files can make credentialed requests"
            elif acao == origin and acac == "true":
                vulnerable = True
                severity = "high"
                issue = f"Arbitrary origin '{origin}' reflected with Allow-Credentials: true — full CORS bypass"
            elif acao == origin and origin not in (target, f"https://{target}", f"http://{target}"):
                vulnerable = True
                severity = "medium"
                issue = f"Arbitrary origin '{origin}' reflected in ACAO (no credentials, but policy is overly permissive)"
            elif acao == "*":
                severity = "low"  # wildcard without credentials is acceptable for public APIs
                issue = None

            result = {
                "origin_tested": origin,
                "label": label,
                "acao": acao,
                "acac": acac,
                "status_code": resp.status_code,
                "vulnerable": vulnerable,
                "finding": None,
            }

            if vulnerable and issue:
                result["finding"] = {
                    "origin": origin,
                    "issue": issue,
                    "severity": severity,
                    "acao_value": acao,
                    "credentials_allowed": acac == "true",
                    "recommendation": "Explicitly whitelist allowed origins. Never reflect arbitrary Origin header values. Never combine ACAO: * with Allow-Credentials: true.",
                }

            return result

        except Exception as e:
            return {
                "origin_tested": origin,
                "label": label,
                "acao": None,
                "acac": None,
                "status_code": None,
                "vulnerable": False,
                "finding": None,
                "error": str(e)[:80],
            }
