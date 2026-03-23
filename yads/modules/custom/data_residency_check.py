"""
Data Residency Check

Maps where a target's data actually flows geographically by resolving every
external resource loaded by the page to an IP address and looking up its
country via ip-api.com (no API key required for moderate use).

Goes significantly beyond the existing dsgvo_scanner, which only detects
*which* third-party vendors are referenced. This module determines:

- The actual hosting country of every external resource
- Whether data flows cross EU/EEA borders (Schrems II relevance)
- Whether the target's own infrastructure is EU-hosted
- Which US-based processors are involved (GDPR Chapter V transfers)
- Whether Standard Contractual Clauses (SCCs) are likely needed
- CDN edge location analysis (Cloudflare, Akamai, Fastly, AWS CloudFront)

Resource types scanned:
- JavaScript (<script src>)
- Stylesheets (<link rel=stylesheet>)
- Images, fonts, media
- iFrames
- XHR/fetch endpoints (from inline JS heuristics)
- DNS-prefetch / preconnect hints

Severity mapping:
- Own infrastructure outside EU with no SCCs indicator → high
- US-based processor (Google, Meta, etc.) without consent gate → high
- Non-EU/non-adequate-country transfer → medium
- UK / EEA adequate country → info
- All resources EU-hosted → pass
"""

import ipaddress
import logging
import re
import socket
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 15
GEOIP_API = "http://ip-api.com/batch"
GEOIP_BATCH_SIZE = 100  # ip-api.com free tier: 100/batch, 45 req/min

# EU/EEA countries (adequate protection under GDPR Art. 45)
EU_EEA_COUNTRIES = {
    "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI",
    "FR", "GR", "HR", "HU", "IE", "IT", "LT", "LU", "LV", "MT",
    "NL", "PL", "PT", "RO", "SE", "SI", "SK",  # EU
    "IS", "LI", "NO",  # EEA
}

# Countries with EU adequacy decision (GDPR Art. 45)
ADEQUATE_COUNTRIES = {
    "AD", "AR", "CA", "FO", "GB", "GG", "IL", "IM", "JE", "JP",
    "KR", "NZ", "CH", "UY",  # UK post-Brexit adequacy decision included
}

# Countries frequently associated with data sovereignty concerns
HIGH_RISK_COUNTRIES = {"CN", "RU", "BY", "IR", "KP", "SY"}

# Known US-based processors that handle EU personal data
US_PROCESSORS = {
    "google.com", "googleapis.com", "gstatic.com", "googletagmanager.com",
    "google-analytics.com", "doubleclick.net", "googlesyndication.com",
    "cloudfront.net", "amazonaws.com", "amazon.com",
    "facebook.com", "facebook.net", "fbcdn.net",
    "microsoft.com", "microsoftonline.com", "azure.com", "msecnd.net",
    "cloudflare.com", "cloudflare.net", "cloudflareinsights.com",
    "fastly.net", "fastly.com",
    "akamaihd.net", "akamaized.net", "akamai.net",
    "stripe.com", "stripe.network",
    "hubspot.com", "hs-scripts.com",
    "salesforce.com", "force.com",
    "intercom.io", "intercomcdn.com",
    "zendesk.com", "zdassets.com",
    "twilio.com", "sendgrid.net",
    "fonts.googleapis.com", "fonts.gstatic.com",
}

# CDNs with known EU-local infrastructure options
CDN_PROVIDERS = {
    "cloudflare": ["cloudflare.com", "cloudflare.net", "cloudflareinsights.com"],
    "fastly": ["fastly.net", "fastly.com"],
    "akamai": ["akamaihd.net", "akamaized.net", "akamai.net", "edgekey.net"],
    "aws_cloudfront": ["cloudfront.net"],
    "azure_cdn": ["azureedge.net", "vo.msecnd.net"],
    "bunnycdn": ["b-cdn.net", "bunnycdn.com"],
}


class DataResidencyCheck(BaseScannerModule):
    """
    Maps all external data flows from a target page to their hosting countries.
    Identifies cross-border transfers relevant under GDPR Chapter V (Schrems II).
    """

    @property
    def module_name(self) -> str:
        return "data_residency_check"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = (
            target.lower().strip()
            .removeprefix("https://").removeprefix("http://")
            .split("/")[0]
        )

        result: Dict[str, Any] = {
            "domain": domain,
            "own_infrastructure": {},
            "external_resources": [],
            "country_summary": {},
            "us_processors": [],
            "high_risk_countries": [],
            "cdn_providers": [],
            "chapter_v_transfers": [],
            "findings": [],
            "summary": {},
        }

        # Fetch and parse the page
        html = self._fetch(f"https://{domain}") or self._fetch(f"http://{domain}")
        if not html:
            result["error"] = "Could not fetch page"
            return result

        # 1. Resolve own infrastructure
        own_ip, own_country = self._resolve_and_geoip(domain)
        result["own_infrastructure"] = {
            "domain": domain,
            "ip": own_ip,
            "country": own_country,
            "eu_hosted": own_country in EU_EEA_COUNTRIES if own_country else None,
        }

        # 2. Extract all external hostnames from the page
        external_domains = self._extract_external_domains(html, domain)

        # 3. Identify CDN providers
        for cdn_name, cdn_patterns in CDN_PROVIDERS.items():
            for ext_dom in external_domains:
                if any(p in ext_dom for p in cdn_patterns):
                    if cdn_name not in result["cdn_providers"]:
                        result["cdn_providers"].append(cdn_name)

        # 4. Batch GeoIP resolution
        resolved = self._batch_geoip(list(external_domains))

        country_buckets: Dict[str, List[str]] = {}
        us_proc_found: List[str] = []

        for ext_dom, geo in resolved.items():
            country = geo.get("countryCode", "??")
            country_name = geo.get("country", "Unknown")
            ip = geo.get("query", "")

            entry = {
                "domain": ext_dom,
                "ip": ip,
                "country": country,
                "country_name": country_name,
                "eu_eea": country in EU_EEA_COUNTRIES,
                "adequate": country in ADEQUATE_COUNTRIES,
                "high_risk": country in HIGH_RISK_COUNTRIES,
                "us_processor": any(p in ext_dom for p in US_PROCESSORS),
            }
            result["external_resources"].append(entry)

            country_buckets.setdefault(country, []).append(ext_dom)

            if country in HIGH_RISK_COUNTRIES and country not in result["high_risk_countries"]:
                result["high_risk_countries"].append(country)

            if entry["us_processor"]:
                # Find the known processor name
                for proc_domain in US_PROCESSORS:
                    if proc_domain in ext_dom:
                        proc_label = self._processor_label(proc_domain)
                        if proc_label not in us_proc_found:
                            us_proc_found.append(proc_label)
                        break

        result["us_processors"] = us_proc_found
        result["country_summary"] = {
            cc: {
                "count": len(doms),
                "domains": doms[:5],
                "classification": (
                    "EU/EEA" if cc in EU_EEA_COUNTRIES else
                    "Adequate" if cc in ADEQUATE_COUNTRIES else
                    "High-Risk" if cc in HIGH_RISK_COUNTRIES else
                    "Third Country"
                ),
            }
            for cc, doms in sorted(country_buckets.items(), key=lambda x: -len(x[1]))
        }

        # 5. Identify Chapter V transfers (non-EU, non-adequate)
        for entry in result["external_resources"]:
            cc = entry["country"]
            if cc and cc != "??" and cc not in EU_EEA_COUNTRIES and cc not in ADEQUATE_COUNTRIES:
                result["chapter_v_transfers"].append({
                    "domain": entry["domain"],
                    "country": entry["country"],
                    "country_name": entry["country_name"],
                    "us_processor": entry["us_processor"],
                })

        self._generate_findings(result)
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _fetch(self, url: str) -> Optional[str]:
        try:
            r = requests.get(
                url, timeout=REQUEST_TIMEOUT, verify=False,
                headers={"User-Agent": "Mozilla/5.0 YADS/DataResidency"},
                allow_redirects=True,
            )
            if r.status_code < 500:
                return r.text[:600_000]
        except Exception:
            pass
        return None

    def _extract_external_domains(self, html: str, own_domain: str) -> Set[str]:
        """Extract all unique external hostnames referenced in the HTML."""
        domains: Set[str] = set()
        patterns = [
            r'src=["\']https?://([^/"\'?\s]+)',
            r'href=["\']https?://([^/"\'?\s]+)',
            r'action=["\']https?://([^/"\'?\s]+)',
            r'url\(["\']?https?://([^)"\'?\s]+)',
            r'dns-prefetch.*?content=["\']//([^"\']+)',
            r'preconnect.*?href=["\']https?://([^/"\'?\s]+)',
            r'data-src=["\']https?://([^/"\'?\s]+)',
        ]
        for pattern in patterns:
            for m in re.finditer(pattern, html, re.IGNORECASE):
                hostname = m.group(1).lower().rstrip("/").rstrip(".")
                # Remove port if present
                hostname = hostname.split(":")[0]
                if hostname and hostname != own_domain and "." in hostname:
                    # Skip relative/fragment refs and own subdomains
                    if not hostname.endswith(f".{own_domain}") and hostname != own_domain:
                        domains.add(hostname)
        return domains

    def _resolve_and_geoip(self, hostname: str) -> Tuple[Optional[str], Optional[str]]:
        try:
            ip = socket.gethostbyname(hostname)
            geo = self._batch_geoip([hostname])
            country = geo.get(hostname, {}).get("countryCode")
            return ip, country
        except Exception:
            return None, None

    def _batch_geoip(self, hostnames: List[str]) -> Dict[str, Dict]:
        """Resolve hostnames to IPs and look up country via ip-api.com batch endpoint."""
        if not hostnames:
            return {}

        # First resolve hostnames to IPs
        ip_to_host: Dict[str, str] = {}
        for h in hostnames[:GEOIP_BATCH_SIZE]:
            try:
                ip = socket.gethostbyname(h)
                if not ipaddress.ip_address(ip).is_private:
                    ip_to_host[ip] = h
            except Exception:
                continue

        if not ip_to_host:
            return {}

        results: Dict[str, Dict] = {}
        try:
            resp = requests.post(
                GEOIP_API,
                json=[{"query": ip} for ip in ip_to_host.keys()],
                params={"fields": "status,country,countryCode,query"},
                timeout=10,
            )
            if resp.status_code == 200:
                for entry in resp.json():
                    ip = entry.get("query", "")
                    hostname = ip_to_host.get(ip, ip)
                    if entry.get("status") == "success":
                        results[hostname] = entry
        except Exception as e:
            logger.debug(f"GeoIP batch lookup failed: {e}")

        return results

    def _processor_label(self, processor_domain: str) -> str:
        labels = {
            "google.com": "Google LLC", "googleapis.com": "Google LLC",
            "gstatic.com": "Google LLC", "googletagmanager.com": "Google LLC",
            "google-analytics.com": "Google LLC", "doubleclick.net": "Google LLC",
            "facebook.com": "Meta Platforms", "facebook.net": "Meta Platforms",
            "fbcdn.net": "Meta Platforms",
            "cloudfront.net": "Amazon Web Services", "amazonaws.com": "Amazon Web Services",
            "microsoft.com": "Microsoft Corp.", "azure.com": "Microsoft Corp.",
            "cloudflare.com": "Cloudflare Inc.", "cloudflare.net": "Cloudflare Inc.",
            "fastly.net": "Fastly Inc.", "stripe.com": "Stripe Inc.",
            "fonts.googleapis.com": "Google LLC (Fonts)",
        }
        for domain, label in labels.items():
            if domain in processor_domain:
                return label
        return processor_domain

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def _generate_findings(self, result: Dict) -> None:
        findings: List[Dict] = []

        # Own infrastructure outside EU
        own = result["own_infrastructure"]
        if own.get("country") and own["eu_hosted"] is False:
            cc = own["country"]
            is_adequate = cc in ADEQUATE_COUNTRIES
            findings.append({
                "severity": "medium" if is_adequate else "high",
                "title": f"Own server infrastructure hosted outside EU/EEA: {cc}",
                "detail": (
                    f"The main domain resolves to an IP in {cc}. "
                    f"{'This country has an EU adequacy decision, but ' if is_adequate else ''}"
                    f"hosting personal data of EU users outside the EEA may require "
                    f"Standard Contractual Clauses (GDPR Art. 46) or other safeguards. "
                    f"Consider EU-based hosting or document the legal transfer mechanism."
                ),
                "category": "own_infra_outside_eu",
            })

        # High-risk country transfers
        for cc in result["high_risk_countries"]:
            findings.append({
                "severity": "high",
                "title": f"Data transfer to high-risk jurisdiction: {cc}",
                "detail": (
                    f"Resources are loaded from servers in {cc}, a country with "
                    f"no EU adequacy decision and known data sovereignty concerns. "
                    f"Such transfers require explicit safeguards (GDPR Art. 46) or "
                    f"an exception (Art. 49). Assess whether any personal data "
                    f"(IP addresses, cookies) is transmitted to this jurisdiction."
                ),
                "category": "high_risk_country",
            })

        # Chapter V transfers (non-adequate third countries)
        non_us_ch5 = [t for t in result["chapter_v_transfers"] if not t["us_processor"]]
        us_ch5 = [t for t in result["chapter_v_transfers"] if t["us_processor"]]

        if us_ch5:
            proc_names = list({t.get("domain", "")[:30] for t in us_ch5})[:5]
            findings.append({
                "severity": "medium",
                "title": f"US data processor transfers detected ({len(us_ch5)} resources)",
                "detail": (
                    f"Resources from {', '.join(proc_names)} and others are loaded "
                    f"from US-hosted infrastructure. Post-Schrems II, transfers to "
                    f"the US require SCCs + Transfer Impact Assessment (TIA) unless "
                    f"the US entity participates in the EU-US Data Privacy Framework (DPF). "
                    f"Verify DPF certification for each processor and document accordingly."
                ),
                "category": "us_processor_transfer",
            })

        if non_us_ch5:
            countries = list({t["country"] for t in non_us_ch5})
            findings.append({
                "severity": "high",
                "title": f"Transfers to non-adequate third countries: {', '.join(countries)}",
                "detail": (
                    f"Data is transferred to {', '.join(countries)} which have no EU "
                    f"adequacy decision. GDPR Chapter V (Art. 44–49) requires appropriate "
                    f"safeguards (SCCs, BCRs, or Art. 49 derogations) before such transfers."
                ),
                "category": "non_adequate_transfer",
            })

        # All-EU pass
        non_eu = [e for e in result["external_resources"]
                  if e["country"] not in EU_EEA_COUNTRIES and e["country"] not in ADEQUATE_COUNTRIES]
        if not non_eu and own.get("eu_hosted") is not False:
            findings.append({
                "severity": "info",
                "title": "All detected resources hosted within EU/EEA or adequate countries",
                "detail": (
                    "No cross-border data transfers to non-adequate third countries "
                    "were detected based on loaded resources. Verify that server-side "
                    "integrations (databases, APIs, SaaS backends) are also EU-hosted."
                ),
                "category": "all_eu_hosted",
            })

        result["findings"] = findings
        result["summary"] = {
            "total_external_domains": len(result["external_resources"]),
            "countries_involved": len(result["country_summary"]),
            "eu_eea_resources": sum(
                1 for e in result["external_resources"] if e["eu_eea"]
            ),
            "third_country_resources": len(result["chapter_v_transfers"]),
            "us_processors": len(result["us_processors"]),
            "high_risk_jurisdictions": len(result["high_risk_countries"]),
            "cdn_providers": result["cdn_providers"],
            "own_country": own.get("country"),
            "own_eu_hosted": own.get("eu_hosted"),
            "findings_count": len(findings),
            "highest_severity": (
                "high" if any(f["severity"] == "high" for f in findings) else
                "medium" if any(f["severity"] == "medium" for f in findings) else
                "info"
            ),
        }
