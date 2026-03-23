"""
Third-Party Risk Scanner

Assesses the security posture of third-party domains referenced in a target's
web application — scripts, stylesheets, fonts, iframes, images loaded from
external origins.

Unlike data_residency_check (which maps geography), this module scans the
*security health* of each third-party dependency:

- SSL certificate validity and days until expiry
- Security headers: HSTS, X-Frame-Options, CSP, X-Content-Type-Options
- URLhaus threat intelligence feed check (abuse.ch)
- Open redirect heuristic detection
- Per-dependency risk score (0–100)
- Aggregated supply chain risk score

Severity mapping:
- Third-party on URLhaus blocklist → critical
- Expired SSL on third-party → high
- SSL expiring within 14 days → high
- Missing HSTS on a third-party carrying scripts → medium
- No security headers at all → low
- Good posture → info/pass
"""

import logging
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 8
MAX_THIRD_PARTIES = 15
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/host/"

# Weight for each resource type — scripts are the highest risk as they execute
_RESOURCE_TYPE_WEIGHT = {
    "script": 10,
    "iframe": 8,
    "link": 4,
    "img": 2,
    "other": 1,
}

# Patterns for resource type extraction
_RESOURCE_PATTERNS: List[Tuple[str, str]] = [
    # (pattern, resource_type)
    (r'<script[^>]+src=["\']https?://([^/"\'?\s#]+)', "script"),
    (r'<link[^>]+href=["\']https?://([^/"\'?\s#]+)', "link"),
    (r'<iframe[^>]+src=["\']https?://([^/"\'?\s#]+)', "iframe"),
    (r'<img[^>]+src=["\']https?://([^/"\'?\s#]+)', "img"),
    (r'url\(["\']?https?://([^)"\'?\s]+)', "other"),
    (r'data-src=["\']https?://([^/"\'?\s#]+)', "img"),
]

# Open redirect path indicators
_REDIRECT_PATHS = [
    "/redirect", "/out", "/go", "/click", "/track", "/r/",
    "?url=", "?redirect=", "?next=", "?target=", "?link=",
    "?return=", "?continue=", "?to=",
]


class ThirdPartyRisk(BaseScannerModule):
    """
    Extracts every external dependency loaded by a target's web application
    and independently assesses each one's security posture — SSL validity,
    security headers, and threat intelligence feed membership.
    """

    @property
    def module_name(self) -> str:
        return "third_party_risk"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = (
            target.lower().strip()
            .removeprefix("https://").removeprefix("http://")
            .split("/")[0]
        )
        url = f"https://{domain}"

        result: Dict[str, Any] = {
            "domain": domain,
            "third_parties": [],
            "high_risk_count": 0,
            "supply_chain_score": 0,
            "findings": [],
            "summary": {},
        }

        # 1. Fetch main page
        html = self._fetch_page(url) or self._fetch_page(f"http://{domain}")
        if not html:
            result["error"] = "Could not fetch target page"
            result["findings"].append({
                "severity": "info",
                "title": "Could not fetch target page for third-party analysis",
                "detail": f"Failed to retrieve {url}. Third-party risk analysis could not be performed.",
                "category": "fetch_error",
            })
            result["summary"] = {"error": True, "findings_count": 1}
            return result

        # 2. Extract and rank third-party domains
        domain_scores = self._extract_domain_scores(html, domain)
        # Sort by weight descending, take top N
        ranked = sorted(domain_scores.items(), key=lambda x: -x[1])[:MAX_THIRD_PARTIES]
        third_party_domains = [d for d, _ in ranked]

        # 3. Assess each third party
        all_risk_scores: List[int] = []
        for tp_domain in third_party_domains:
            assessment = self._assess_third_party(tp_domain)
            result["third_parties"].append(assessment)
            all_risk_scores.append(assessment["risk_score"])

            # Generate per-dependency findings
            self._generate_dependency_findings(assessment, result["findings"])

        # 4. Aggregate
        if all_risk_scores:
            result["supply_chain_score"] = round(sum(all_risk_scores) / len(all_risk_scores))
            result["high_risk_count"] = sum(1 for s in all_risk_scores if s >= 60)

        # 5. Aggregate findings
        self._generate_aggregate_findings(result)

        result["summary"] = {
            "domain": domain,
            "third_parties_assessed": len(result["third_parties"]),
            "supply_chain_risk_score": result["supply_chain_score"],
            "high_risk_dependencies": result["high_risk_count"],
            "findings_count": len(result["findings"]),
            "highest_severity": (
                "critical" if any(f["severity"] == "critical" for f in result["findings"]) else
                "high" if any(f["severity"] == "high" for f in result["findings"]) else
                "medium" if any(f["severity"] == "medium" for f in result["findings"]) else
                "low" if any(f["severity"] == "low" for f in result["findings"]) else
                "info" if result["findings"] else "pass"
            ),
        }

        return result

    # ------------------------------------------------------------------
    # Extraction helpers
    # ------------------------------------------------------------------

    def _extract_domain_scores(self, html: str, own_domain: str) -> Dict[str, int]:
        """Extract external domains weighted by resource type importance."""
        domain_scores: Dict[str, int] = {}
        for pattern, rtype in _RESOURCE_PATTERNS:
            for m in re.finditer(pattern, html, re.IGNORECASE):
                hostname = m.group(1).lower().rstrip("/").rstrip(".")
                hostname = hostname.split(":")[0]
                if not hostname or "." not in hostname:
                    continue
                if hostname == own_domain or hostname.endswith(f".{own_domain}"):
                    continue
                weight = _RESOURCE_TYPE_WEIGHT.get(rtype, 1)
                domain_scores[hostname] = domain_scores.get(hostname, 0) + weight
        return domain_scores

    # ------------------------------------------------------------------
    # Per-domain assessment
    # ------------------------------------------------------------------

    def _assess_third_party(self, domain: str) -> Dict[str, Any]:
        """Run all security checks on a single third-party domain."""
        assessment: Dict[str, Any] = {
            "domain": domain,
            "ssl": {},
            "headers": {},
            "urlhaus": {},
            "open_redirect": False,
            "risk_score": 0,
            "risk_factors": [],
        }

        # SSL check
        ssl_result = self._check_ssl(domain)
        assessment["ssl"] = ssl_result

        # HTTP security headers check
        headers_result = self._check_security_headers(domain)
        assessment["headers"] = headers_result

        # URLhaus threat feed check
        urlhaus_result = self._check_urlhaus(domain)
        assessment["urlhaus"] = urlhaus_result

        # Open redirect heuristic
        assessment["open_redirect"] = self._check_open_redirect(domain)

        # Calculate risk score 0-100
        score = 0
        factors = []

        if urlhaus_result.get("listed"):
            score += 50
            factors.append("urlhaus_listed")

        ssl_days = ssl_result.get("days_remaining")
        if ssl_result.get("error") and ssl_result.get("reachable"):
            score += 30
            factors.append("ssl_error")
        elif ssl_days is not None:
            if ssl_days < 0:
                score += 30
                factors.append("ssl_expired")
            elif ssl_days < 14:
                score += 20
                factors.append("ssl_expiring_soon")
            elif ssl_days < 30:
                score += 10
                factors.append("ssl_expiring_30d")

        hdr = headers_result.get("present", {})
        missing_headers = 0
        if not hdr.get("hsts"):
            score += 5
            missing_headers += 1
            factors.append("no_hsts")
        if not hdr.get("csp"):
            score += 3
            missing_headers += 1
            factors.append("no_csp")
        if not hdr.get("x_frame_options"):
            score += 3
            missing_headers += 1
            factors.append("no_x_frame")
        if not hdr.get("x_content_type"):
            score += 2
            missing_headers += 1
            factors.append("no_xcto")

        if assessment["open_redirect"]:
            score += 10
            factors.append("open_redirect_suspected")

        assessment["risk_score"] = min(score, 100)
        assessment["risk_factors"] = factors

        return assessment

    def _check_ssl(self, domain: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {"reachable": False, "valid": None, "days_remaining": None,
                                   "expires": None, "issuer": None, "error": None}
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.create_connection((domain, 443), timeout=REQUEST_TIMEOUT),
                server_hostname=domain
            ) as ssock:
                cert = ssock.getpeercert()
                result["reachable"] = True
                result["valid"] = True
                not_after_str = cert.get("notAfter", "")
                if not_after_str:
                    # Format: "Jan  1 00:00:00 2026 GMT"
                    try:
                        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        not_after = not_after.replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        days = (not_after - now).days
                        result["days_remaining"] = days
                        result["expires"] = not_after_str
                    except ValueError:
                        pass
                issuer = dict(x[0] for x in cert.get("issuer", []))
                result["issuer"] = issuer.get("organizationName", issuer.get("commonName", "Unknown"))
        except ssl.SSLCertVerificationError as e:
            result["reachable"] = True
            result["valid"] = False
            result["error"] = str(e)[:200]
        except ssl.SSLError as e:
            result["reachable"] = True
            result["valid"] = False
            result["error"] = str(e)[:200]
        except (socket.timeout, socket.gaierror, OSError):
            result["reachable"] = False
        except Exception as e:
            result["error"] = str(e)[:200]
        return result

    def _check_security_headers(self, domain: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "reachable": False,
            "present": {
                "hsts": False,
                "csp": False,
                "x_frame_options": False,
                "x_content_type": False,
            },
            "raw": {},
        }
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}/"
            try:
                resp = requests.head(
                    url, timeout=REQUEST_TIMEOUT, verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 YADS/ThirdPartyRisk"},
                )
                result["reachable"] = True
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                result["present"]["hsts"] = "strict-transport-security" in hdrs
                result["present"]["csp"] = "content-security-policy" in hdrs
                result["present"]["x_frame_options"] = "x-frame-options" in hdrs
                result["present"]["x_content_type"] = "x-content-type-options" in hdrs
                # Store relevant raw values (truncated)
                for h in ("strict-transport-security", "content-security-policy",
                          "x-frame-options", "x-content-type-options"):
                    if h in hdrs:
                        result["raw"][h] = hdrs[h][:120]
                return result
            except Exception:
                continue
        return result

    def _check_urlhaus(self, domain: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {"listed": False, "threat": None, "urls_count": 0, "error": None}
        try:
            resp = requests.post(
                URLHAUS_API,
                data={"host": domain},
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": "YADS/ThirdPartyRisk"},
            )
            if resp.status_code == 200:
                data = resp.json()
                query_status = data.get("query_status", "no_results")
                if query_status == "is_host":
                    result["listed"] = True
                    urls = data.get("urls", [])
                    result["urls_count"] = len(urls)
                    # Extract most recent threat type
                    threats = [u.get("threat") for u in urls if u.get("threat")]
                    if threats:
                        result["threat"] = threats[0]
                elif query_status in ("no_results", "invalid_host"):
                    result["listed"] = False
        except Exception as e:
            result["error"] = str(e)[:200]
        return result

    def _check_open_redirect(self, domain: str) -> bool:
        """Heuristic: check if the domain has common open redirect endpoints."""
        for path in _REDIRECT_PATHS:
            if path.startswith("?"):
                # Query param patterns
                test_url = f"https://{domain}/{path}https://example.com"
            else:
                test_url = f"https://{domain}{path}"
            try:
                resp = requests.get(
                    test_url, timeout=3, verify=False, allow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0 YADS/ThirdPartyRisk"},
                )
                # If redirecting to a non-domain URL, flag as potential open redirect
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if location.startswith("http") and domain not in location:
                        return True
            except Exception:
                continue
        return False

    # ------------------------------------------------------------------
    # Fetch helper
    # ------------------------------------------------------------------

    def _fetch_page(self, url: str) -> Optional[str]:
        try:
            resp = requests.get(
                url, timeout=REQUEST_TIMEOUT + 5, verify=False,
                headers={"User-Agent": "Mozilla/5.0 YADS/ThirdPartyRisk"},
                allow_redirects=True,
            )
            if resp.status_code < 500:
                return resp.text[:800_000]
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Findings generation
    # ------------------------------------------------------------------

    def _generate_dependency_findings(self, assessment: Dict, findings: List[Dict]) -> None:
        domain = assessment["domain"]
        factors = assessment.get("risk_factors", [])

        # URLhaus blocklist → critical
        if "urlhaus_listed" in factors:
            threat = assessment["urlhaus"].get("threat") or "malware/phishing"
            urls_count = assessment["urlhaus"].get("urls_count", 0)
            findings.append({
                "severity": "critical",
                "title": f"Third-party on URLhaus blocklist: {domain}",
                "detail": (
                    f"The domain {domain} is listed in the URLhaus threat feed (abuse.ch) "
                    f"as a {threat} host with {urls_count} known malicious URL(s). "
                    f"This domain is loaded as a dependency in your web application. "
                    f"A compromised or malicious third-party loading into your app is "
                    f"indistinguishable to users from your own content — remove or replace immediately."
                ),
                "category": "third_party_urlhaus",
            })

        # Expired SSL → high
        if "ssl_expired" in factors:
            days = assessment["ssl"].get("days_remaining", 0)
            findings.append({
                "severity": "high",
                "title": f"Expired SSL certificate on third-party: {domain}",
                "detail": (
                    f"The TLS certificate for {domain} expired {abs(days)} day(s) ago. "
                    f"An expired certificate indicates the operator has either abandoned "
                    f"the domain or is not actively maintaining it — both are supply chain risk signals. "
                    f"Browsers may show warnings or block mixed content if this resource is loaded."
                ),
                "category": "third_party_ssl_expired",
            })
        elif "ssl_expiring_soon" in factors:
            days = assessment["ssl"].get("days_remaining", 0)
            findings.append({
                "severity": "high",
                "title": f"SSL certificate expiring in {days} days on third-party: {domain}",
                "detail": (
                    f"The TLS certificate for {domain} expires in {days} day(s). "
                    f"If not renewed, browsers will block the resource, breaking functionality. "
                    f"Monitor this dependency or pre-emptively replace it."
                ),
                "category": "third_party_ssl_expiring",
            })
        elif "ssl_error" in factors:
            err = assessment["ssl"].get("error", "")
            findings.append({
                "severity": "high",
                "title": f"SSL certificate error on third-party: {domain}",
                "detail": (
                    f"The TLS certificate for {domain} could not be validated: {err[:200]}. "
                    f"This may indicate a self-signed certificate, hostname mismatch, or "
                    f"certificate chain issue. Resources served over invalid TLS can be intercepted."
                ),
                "category": "third_party_ssl_error",
            })

        # Missing HSTS on script-loading domain → medium
        ssl_ok = assessment["ssl"].get("valid") is True
        if "no_hsts" in factors and ssl_ok:
            findings.append({
                "severity": "medium",
                "title": f"Missing HSTS on third-party dependency: {domain}",
                "detail": (
                    f"The third-party domain {domain} does not set a Strict-Transport-Security header. "
                    f"Without HSTS, connections to this dependency could be downgraded to HTTP "
                    f"via network-level attacks (SSL-stripping), compromising the integrity "
                    f"of scripts or resources loaded from this host."
                ),
                "category": "third_party_no_hsts",
            })

        # All security headers missing → low
        if all(k in factors for k in ("no_hsts", "no_csp", "no_x_frame", "no_xcto")):
            if assessment["headers"].get("reachable"):
                findings.append({
                    "severity": "low",
                    "title": f"No security headers on third-party: {domain}",
                    "detail": (
                        f"The domain {domain} serves responses with no HTTP security headers "
                        f"(HSTS, CSP, X-Frame-Options, X-Content-Type-Options). "
                        f"While not critical in isolation, this indicates a low security maturity "
                        f"baseline for this dependency operator."
                    ),
                    "category": "third_party_no_headers",
                })

        # Open redirect suspicion → info
        if "open_redirect_suspected" in factors:
            findings.append({
                "severity": "info",
                "title": f"Potential open redirect on third-party: {domain}",
                "detail": (
                    f"A redirect endpoint was detected on {domain} that may be susceptible to "
                    f"open redirects. If this domain is used for analytics or link tracking, "
                    f"an open redirect could be abused in phishing campaigns targeting your users."
                ),
                "category": "third_party_open_redirect",
            })

    def _generate_aggregate_findings(self, result: Dict) -> None:
        score = result["supply_chain_score"]
        high_risk = result["high_risk_count"]
        total = len(result["third_parties"])

        if total == 0:
            result["findings"].append({
                "severity": "info",
                "title": "No external third-party dependencies detected",
                "detail": "No external script, stylesheet, iframe or image sources were found on the target page.",
                "category": "no_third_parties",
            })
            return

        if score >= 70:
            result["findings"].append({
                "severity": "high",
                "title": f"High aggregate supply chain risk score: {score}/100",
                "detail": (
                    f"The combined risk assessment across {total} third-party dependencies "
                    f"yields a supply chain risk score of {score}/100 ({high_risk} high-risk dependencies). "
                    f"Review and reduce third-party dependencies, especially those with expired certificates "
                    f"or threat feed matches."
                ),
                "category": "high_supply_chain_score",
            })
        elif score >= 40:
            result["findings"].append({
                "severity": "medium",
                "title": f"Moderate aggregate supply chain risk score: {score}/100",
                "detail": (
                    f"The combined risk assessment across {total} third-party dependencies "
                    f"yields a supply chain risk score of {score}/100. "
                    f"Address the individual findings above to reduce exposure."
                ),
                "category": "medium_supply_chain_score",
            })
        else:
            result["findings"].append({
                "severity": "info",
                "title": f"Third-party supply chain risk score: {score}/100",
                "detail": (
                    f"Assessed {total} third-party dependencies. "
                    f"Overall supply chain risk is low (score: {score}/100). "
                    f"Continue monitoring for changes in dependency posture."
                ),
                "category": "low_supply_chain_score",
            })
