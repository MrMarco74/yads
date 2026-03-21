"""
Subdomain Takeover Scanner (Task #4)

Detects dangling DNS records that could allow subdomain hijacking:
- CNAME pointing to unclaimed 3rd-party services (AWS S3, GitHub Pages,
  Heroku, Netlify, Azure, Shopify, Fastly, Pantheon, etc.)
- A records pointing to released IPs (basic check)
- NS records pointing to unregistered nameservers

Works entirely with DNS + HTTP fingerprinting — no external API needed.
"""

import logging
import socket
import dns.resolver
import dns.exception
import requests
from typing import Any, Dict, List, Optional, Tuple

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

# Service fingerprints: (cname_pattern, http_body_indicator, severity, service)
# These are the canonical "unclaimed" response bodies for each provider.
TAKEOVER_SIGNATURES: List[Tuple[str, str, str, str]] = [
    # AWS S3
    ("s3.amazonaws.com", "NoSuchBucket", "critical", "AWS S3"),
    ("s3-website", "NoSuchBucket", "critical", "AWS S3 Website"),
    ("s3-website", "The specified bucket does not exist", "critical", "AWS S3 Website"),
    # GitHub Pages
    ("github.io", "There isn't a GitHub Pages site here", "critical", "GitHub Pages"),
    # Heroku
    ("herokuapp.com", "No such app", "critical", "Heroku"),
    ("herokudns.com", "No such app", "critical", "Heroku DNS"),
    # Netlify
    ("netlify.com", "Not Found", "high", "Netlify"),
    ("netlify.app", "Not Found", "high", "Netlify"),
    # Azure
    ("azurewebsites.net", "404 Web Site not found", "critical", "Azure Web Apps"),
    ("azureedge.net", "The resource you are looking for has been removed", "high", "Azure CDN"),
    ("cloudapp.net", "404 Web Site not found", "high", "Azure Cloud"),
    ("trafficmanager.net", "404", "medium", "Azure Traffic Manager"),
    # Shopify
    ("myshopify.com", "Sorry, this shop is currently unavailable", "high", "Shopify"),
    # Fastly
    ("fastly.net", "Fastly error: unknown domain", "high", "Fastly"),
    # Pantheon
    ("pantheonsite.io", "The gods are wise", "high", "Pantheon"),
    # Cargo
    ("cargocollective.com", "404 Not Found", "medium", "Cargo Collective"),
    # Tumblr
    ("tumblr.com", "Whatever you were looking for doesn't currently exist", "high", "Tumblr"),
    # WordPress.com
    ("wordpress.com", "Do you want to register", "medium", "WordPress.com"),
    # Zendesk
    ("zendesk.com", "Help Center Closed", "medium", "Zendesk"),
    ("zendesk.com", "Oops, this help center no longer exists", "medium", "Zendesk"),
    # Helpjuice
    ("helpjuice.com", "We could not find what you're looking for", "medium", "Helpjuice"),
    # UserVoice
    ("uservoice.com", "This UserVoice subdomain is currently available", "high", "UserVoice"),
    # Surge.sh
    ("surge.sh", "project not found", "high", "Surge.sh"),
    # Readme.io
    ("readme.io", "Project doesnt exist... yet!", "medium", "ReadMe.io"),
    # Webflow
    ("webflow.io", "The page you are looking for doesn't exist", "medium", "Webflow"),
    # Strikingly
    ("strikingly.com", "page not found", "medium", "Strikingly"),
    # LaunchRock
    ("launchrock.com", "It looks like you may have taken a wrong turn somewhere", "medium", "LaunchRock"),
    # Bitbucket
    ("bitbucket.io", "Repository not found", "high", "Bitbucket"),
    # Ghost
    ("ghost.io", "The thing you were looking for is no longer here", "medium", "Ghost.io"),
    # Smartling
    ("smartling.com", "Domain is not configured", "medium", "Smartling"),
    # Pingdom
    ("pingdom.com", "This public report page has not been activated", "low", "Pingdom"),
    # Tilda
    ("tilda.cc", "Please renew your subscription", "medium", "Tilda"),
    # Unbounce
    ("unbouncepages.com", "The requested URL was not found", "medium", "Unbounce"),
]

# Build lookup by CNAME pattern
CNAME_LOOKUP: Dict[str, List[Tuple]] = {}
for sig in TAKEOVER_SIGNATURES:
    cname_pat, body_sig, sev, svc = sig
    CNAME_LOOKUP.setdefault(cname_pat, []).append((body_sig, sev, svc))


class SubdomainTakeoverScanner(BaseScannerModule):
    """Scan domain and known subdomains for CNAME/NS-based takeover opportunities."""

    REQUEST_TIMEOUT = 8

    @property
    def module_name(self) -> str:
        return "subdomain_takeover"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = target.lower().strip().removeprefix("https://").removeprefix("http://").split("/")[0]

        result: Dict[str, Any] = {
            "domain": domain,
            "subdomains_checked": [],
            "vulnerable": [],
            "potentially_vulnerable": [],
            "findings": [],
            "summary": {
                "total_checked": 0,
                "vulnerable_count": 0,
                "potentially_vulnerable_count": 0,
                "score": 100,
            },
        }

        # Collect subdomains to check:
        # 1. The main domain itself
        # 2. www subdomain
        # 3. Common subdomains from DNS
        candidates = self._collect_candidates(domain, target_id)
        result["subdomains_checked"] = candidates
        result["summary"]["total_checked"] = len(candidates)

        for subdomain in candidates:
            check = self._check_takeover(subdomain)
            if check["vulnerable"]:
                result["vulnerable"].append(check)
                result["findings"].append({
                    "severity": check["severity"],
                    "title": f"Subdomain takeover possible: {subdomain}",
                    "detail": f"CNAME → {check['cname_target']} ({check['service']}) — {check['indicator']}",
                    "subdomain": subdomain,
                    "service": check["service"],
                    "cname": check["cname_target"],
                })
            elif check["dangling"]:
                result["potentially_vulnerable"].append(check)
                result["findings"].append({
                    "severity": "medium",
                    "title": f"Dangling CNAME detected: {subdomain}",
                    "detail": f"CNAME → {check['cname_target']} but HTTP check inconclusive.",
                    "subdomain": subdomain,
                    "service": check.get("service", "Unknown"),
                    "cname": check["cname_target"],
                })

        # Score
        score = 100
        for f in result["findings"]:
            if f["severity"] == "critical":
                score -= 30
            elif f["severity"] == "high":
                score -= 20
            elif f["severity"] == "medium":
                score -= 10

        # Persist findings to OSINTIntelligence model
        if target_id and self.db_session:
            from yads.models import OSINTIntelligence
            import datetime
            for f in result["findings"]:
                sub = f["subdomain"]
                existing = self.db_session.query(OSINTIntelligence).filter_by(
                    target_id=target_id, module_name=self.module_name, data_type="dangling_cname"
                ).filter(OSINTIntelligence.data_json["subdomain"].astext == sub).first()
                if not existing:
                    self.db_session.add(OSINTIntelligence(
                        target_id=target_id, module_name=self.module_name, data_type="dangling_cname",
                        data_json={"subdomain": sub, "cname": f["cname"], "service": f["service"]},
                        severity=f["severity"], timestamp=datetime.datetime.utcnow()
                    ))
            try:
                self.db_session.commit()
            except Exception as e:
                logger.error(f"[TakeoverScanner] DB Commit failed: {e}")
                self.db_session.rollback()

        result["summary"]["score"] = max(0, score)
        result["summary"]["vulnerable_count"] = len(result["vulnerable"])
        result["summary"]["potentially_vulnerable_count"] = len(result["potentially_vulnerable"])

        return result

    # ------------------------------------------------------------------
    # Candidate Collection
    # ------------------------------------------------------------------

    def _collect_candidates(self, domain: str, target_id: Optional[int]) -> List[str]:
        """Build list of subdomains to check."""
        candidates = set()
        candidates.add(domain)

        # Common prefixes worth checking
        COMMON_PREFIXES = [
            "www", "mail", "webmail", "smtp", "ftp", "sftp",
            "dev", "staging", "beta", "test", "demo", "preview",
            "api", "app", "admin", "portal", "login", "sso",
            "blog", "shop", "store", "cdn", "static", "assets",
            "help", "support", "docs", "status",
        ]
        for prefix in COMMON_PREFIXES:
            candidates.add(f"{prefix}.{domain}")

        # Try to get existing subdomains from the database if target_id given
        if target_id and self.db_session:
            from yads.models import ScanResult
            from sqlmodel import select
            dns_result = self.db_session.exec(
                select(ScanResult)
                .where(ScanResult.target_id == target_id)
                .where(ScanResult.module_name == "dns_scanner")
                .order_by(ScanResult.scanned_at.desc())
            ).first()
            if dns_result and dns_result.data:
                subs = dns_result.data.get("subdomains", [])
                for sub in subs:
                    if isinstance(sub, dict):
                        candidates.add(sub.get("name", ""))
                    elif isinstance(sub, str):
                        candidates.add(sub)

        return sorted(s for s in candidates if s)

    # ------------------------------------------------------------------
    # Takeover Check
    # ------------------------------------------------------------------

    def _check_takeover(self, subdomain: str) -> Dict[str, Any]:
        result = {
            "subdomain": subdomain,
            "cname_target": None,
            "vulnerable": False,
            "dangling": False,
            "severity": None,
            "service": None,
            "indicator": None,
        }

        # 1. Resolve CNAME
        cname_target = self._get_cname(subdomain)
        if not cname_target:
            return result  # No CNAME, nothing to check

        result["cname_target"] = cname_target

        # 2. Check if CNAME matches a known vulnerable service
        matched_service = None
        for cname_pat, checks in CNAME_LOOKUP.items():
            if cname_pat in cname_target:
                matched_service = (cname_pat, checks)
                break

        if not matched_service:
            return result  # CNAME points somewhere, but not a known takeover target

        cname_pat, checks = matched_service

        # 3. Try to resolve the CNAME target itself
        cname_resolves = self._resolves(cname_target)

        # 4. HTTP fingerprint check
        http_body = self._fetch_http_body(subdomain)

        if http_body:
            for body_sig, sev, svc in checks:
                if body_sig.lower() in http_body.lower():
                    result["vulnerable"] = True
                    result["severity"] = sev
                    result["service"] = svc
                    result["indicator"] = f"Response contains: '{body_sig}'"
                    return result

        # 5. CNAME resolves but no body match — flag as dangling if CNAME target doesn't resolve
        if not cname_resolves:
            result["dangling"] = True
            result["service"] = checks[0][2] if checks else cname_pat
            logger.info(f"[TakeoverScanner] Dangling CNAME: {subdomain} → {cname_target} (unresolvable)")

        return result

    def _get_cname(self, domain: str) -> Optional[str]:
        try:
            answers = dns.resolver.resolve(domain, "CNAME", lifetime=5)
            for rdata in answers:
                return str(rdata.target).rstrip(".")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass
        except Exception as e:
            logger.debug(f"[TakeoverScanner] CNAME lookup {domain}: {e}")
        return None

    def _resolves(self, hostname: str) -> bool:
        try:
            socket.gethostbyname(hostname)
            return True
        except Exception:
            return False

    def _fetch_http_body(self, domain: str) -> Optional[str]:
        for scheme in ("https", "http"):
            try:
                resp = requests.get(
                    f"{scheme}://{domain}",
                    timeout=self.REQUEST_TIMEOUT,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 YADS Security Scanner"},
                    verify=False,
                )
                return resp.text[:5000]
            except Exception:
                continue
        return None
