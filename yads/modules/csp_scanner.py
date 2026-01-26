"""
CSP (Content-Security-Policy) Scanner Module

Extracts and analyzes Content-Security-Policy headers to discover:
- External domains allowed in various directives
- Potential additional company assets
- Security misconfigurations
- Third-party dependencies
"""

import re
import requests
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from datetime import datetime
from collections import defaultdict
import logging

from yads.core.base import BaseScannerModule

logger = logging.getLogger("yads.csp_scanner")

# CSP directives that contain domain/URL sources
CSP_SOURCE_DIRECTIVES = [
    'default-src',
    'script-src',
    'script-src-elem',
    'script-src-attr',
    'style-src',
    'style-src-elem',
    'style-src-attr',
    'img-src',
    'font-src',
    'connect-src',
    'media-src',
    'object-src',
    'frame-src',
    'child-src',
    'worker-src',
    'manifest-src',
    'prefetch-src',
    'base-uri',
    'form-action',
    'frame-ancestors',
]

# Known third-party services (for categorization)
KNOWN_THIRD_PARTY_PATTERNS = {
    # CDNs
    'cdn': [
        r'cdn\.', r'cdnjs\.', r'jsdelivr\.', r'unpkg\.', r'cloudflare\.com',
        r'fastly\.', r'akamai\.', r'cloudfront\.', r'stackpath\.'
    ],
    # Analytics
    'analytics': [
        r'google-analytics\.', r'googletagmanager\.', r'analytics\.', r'segment\.',
        r'mixpanel\.', r'amplitude\.', r'hotjar\.', r'heap\.', r'fullstory\.'
    ],
    # Social Media
    'social': [
        r'facebook\.', r'fb\.', r'twitter\.', r'linkedin\.', r'instagram\.',
        r'youtube\.', r'tiktok\.', r'pinterest\.', r'snapchat\.'
    ],
    # Advertising
    'advertising': [
        r'doubleclick\.', r'googlesyndication\.', r'googleadservices\.',
        r'adsense\.', r'adroll\.', r'criteo\.', r'outbrain\.', r'taboola\.'
    ],
    # Fonts
    'fonts': [
        r'fonts\.googleapis\.', r'fonts\.gstatic\.', r'use\.typekit\.', r'fast\.fonts\.'
    ],
    # Payment
    'payment': [
        r'stripe\.', r'paypal\.', r'braintree\.', r'square\.', r'adyen\.'
    ],
    # Chat/Support
    'support': [
        r'intercom\.', r'zendesk\.', r'drift\.', r'crisp\.', r'freshdesk\.'
    ],
    # Cloud/Infrastructure
    'cloud': [
        r'amazonaws\.', r'azure\.', r'googleapis\.', r'gstatic\.', r'firebaseapp\.'
    ],
    # Error Tracking
    'monitoring': [
        r'sentry\.', r'bugsnag\.', r'rollbar\.', r'newrelic\.', r'datadoghq\.'
    ]
}


class CSPScanner(BaseScannerModule):
    """Scanner for Content-Security-Policy header analysis."""

    @property
    def module_name(self) -> str:
        return "csp_scanner"

    def __init__(self, db_session=None):
        super().__init__(db_session)
        self.timeout = 15

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        """Execute CSP analysis for a domain."""
        logger.info(f"Starting CSP scan for {target}")

        results = {
            "domain": target,
            "scanned_at": datetime.utcnow().isoformat(),
            "csp_header": None,
            "csp_report_only": None,
            "parsed_directives": {},
            "external_domains": [],
            "potential_assets": [],
            "third_party_services": {},
            "security_findings": [],
            "statistics": {}
        }

        # Fetch headers from HTTPS and HTTP
        headers_https = self._fetch_headers(f"https://{target}")
        headers_http = self._fetch_headers(f"http://{target}")

        # Use HTTPS headers preferentially
        headers = headers_https or headers_http

        if not headers:
            results["error"] = "Could not fetch headers from target"
            return results

        # Extract CSP headers
        csp_header = headers.get('Content-Security-Policy') or headers.get('content-security-policy')
        csp_report_only = headers.get('Content-Security-Policy-Report-Only') or headers.get('content-security-policy-report-only')

        results["csp_header"] = csp_header
        results["csp_report_only"] = csp_report_only

        if not csp_header and not csp_report_only:
            results["security_findings"].append({
                "finding": "No CSP Header",
                "severity": "medium",
                "description": "The website does not implement Content-Security-Policy headers."
            })
            return results

        # Parse CSP header(s)
        csp_to_parse = csp_header or csp_report_only
        parsed = self._parse_csp(csp_to_parse)
        results["parsed_directives"] = parsed

        # Extract all external domains
        all_domains = self._extract_domains(parsed, target)
        results["external_domains"] = sorted(list(all_domains))

        # Categorize domains
        potential_assets, third_party = self._categorize_domains(all_domains, target)
        results["potential_assets"] = potential_assets
        results["third_party_services"] = third_party

        # Security analysis
        findings = self._analyze_security(parsed, csp_header, csp_report_only)
        results["security_findings"] = findings

        # Statistics
        results["statistics"] = {
            "total_external_domains": len(all_domains),
            "potential_company_assets": len(potential_assets),
            "third_party_domains": sum(len(v) for v in third_party.values()),
            "directives_count": len(parsed),
            "has_csp": csp_header is not None,
            "has_csp_report_only": csp_report_only is not None,
            "security_issues": len(findings)
        }

        logger.info(f"CSP scan complete for {target}: found {len(all_domains)} external domains")
        return results

    def _fetch_headers(self, url: str) -> Optional[Dict[str, str]]:
        """Fetch HTTP headers from URL."""
        try:
            response = requests.head(
                url,
                timeout=self.timeout,
                headers={"User-Agent": "YADS Security Scanner"},
                allow_redirects=True,
                verify=True
            )
            return dict(response.headers)
        except requests.exceptions.SSLError:
            try:
                response = requests.head(
                    url,
                    timeout=self.timeout,
                    headers={"User-Agent": "YADS Security Scanner"},
                    allow_redirects=True,
                    verify=False
                )
                return dict(response.headers)
            except:
                return None
        except Exception as e:
            logger.debug(f"Error fetching headers from {url}: {e}")
            return None

    def _parse_csp(self, csp_header: str) -> Dict[str, List[str]]:
        """Parse CSP header into directives and values."""
        directives = {}

        if not csp_header:
            return directives

        # Split by semicolon
        parts = csp_header.split(';')

        for part in parts:
            part = part.strip()
            if not part:
                continue

            # Split directive name from values
            tokens = part.split()
            if not tokens:
                continue

            directive_name = tokens[0].lower()
            values = tokens[1:] if len(tokens) > 1 else []

            directives[directive_name] = values

        return directives

    def _extract_domains(self, parsed: Dict[str, List[str]], target_domain: str) -> Set[str]:
        """Extract all external domains from CSP directives."""
        domains = set()
        target_parts = target_domain.lower().split('.')

        for directive, values in parsed.items():
            if directive not in CSP_SOURCE_DIRECTIVES:
                continue

            for value in values:
                domain = self._extract_domain_from_value(value)
                if domain:
                    # Exclude self-references
                    domain_lower = domain.lower()
                    if not self._is_same_domain(domain_lower, target_domain):
                        domains.add(domain_lower)

        return domains

    def _extract_domain_from_value(self, value: str) -> Optional[str]:
        """Extract domain from a CSP value."""
        # Skip keywords
        keywords = ["'self'", "'unsafe-inline'", "'unsafe-eval'", "'none'",
                    "'strict-dynamic'", "'unsafe-hashes'", "'wasm-unsafe-eval'",
                    "'report-sample'", "data:", "blob:", "filesystem:"]

        value_lower = value.lower()
        if value_lower in keywords or value_lower.startswith("'nonce-") or value_lower.startswith("'sha"):
            return None

        # Handle URLs
        if value.startswith('http://') or value.startswith('https://'):
            try:
                parsed = urlparse(value)
                return parsed.netloc
            except:
                return None

        # Handle wildcards like *.example.com
        if value.startswith('*.'):
            return value[2:]

        # Handle plain domains
        if '.' in value and not value.startswith("'"):
            # Remove port if present
            if ':' in value:
                value = value.split(':')[0]
            return value

        return None

    def _is_same_domain(self, domain1: str, domain2: str) -> bool:
        """Check if two domains are the same or subdomains of each other."""
        d1 = domain1.lower().strip('.')
        d2 = domain2.lower().strip('.')

        if d1 == d2:
            return True

        # Check if one is a subdomain of the other
        if d1.endswith('.' + d2) or d2.endswith('.' + d1):
            return True

        # Extract base domains (simple approach)
        parts1 = d1.split('.')
        parts2 = d2.split('.')

        if len(parts1) >= 2 and len(parts2) >= 2:
            base1 = '.'.join(parts1[-2:])
            base2 = '.'.join(parts2[-2:])
            if base1 == base2:
                return True

        return False

    def _categorize_domains(self, domains: Set[str], target_domain: str) -> Tuple[List[Dict], Dict[str, List[str]]]:
        """Categorize domains into potential assets and third-party services."""
        potential_assets = []
        third_party = defaultdict(list)

        # Extract target's base domain for comparison
        target_parts = target_domain.lower().split('.')
        target_base = '.'.join(target_parts[-2:]) if len(target_parts) >= 2 else target_domain

        for domain in domains:
            domain_lower = domain.lower()

            # Check if it's a known third-party service
            categorized = False
            for category, patterns in KNOWN_THIRD_PARTY_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, domain_lower):
                        third_party[category].append(domain)
                        categorized = True
                        break
                if categorized:
                    break

            if not categorized:
                # Check if it might be a company asset
                # Heuristics: similar domain name, corporate patterns
                domain_parts = domain_lower.split('.')
                domain_base = '.'.join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain_lower

                # Check for brand/company name overlap
                is_potential_asset = False

                # Simple heuristic: check if any part of target domain appears in the external domain
                for part in target_parts:
                    if len(part) > 3 and part in domain_lower:
                        is_potential_asset = True
                        break

                # Check for common corporate patterns
                corporate_patterns = [
                    r'-cdn\.', r'-assets\.', r'-static\.', r'-api\.', r'-app\.',
                    r'cdn-', r'assets-', r'static-', r'api-', r'app-',
                    r'\.corp\.', r'\.internal\.', r'\.dev\.', r'\.staging\.',
                    r'-dev\.', r'-staging\.', r'-prod\.', r'-test\.'
                ]

                for pattern in corporate_patterns:
                    if re.search(pattern, domain_lower):
                        is_potential_asset = True
                        break

                if is_potential_asset:
                    potential_assets.append({
                        "domain": domain,
                        "reason": "Potential company asset based on naming patterns",
                        "priority": "high"
                    })
                else:
                    # Unknown third-party
                    third_party["other"].append(domain)

        # Sort potential assets by priority
        potential_assets.sort(key=lambda x: (0 if x["priority"] == "high" else 1, x["domain"]))

        return potential_assets, dict(third_party)

    def _analyze_security(self, parsed: Dict[str, List[str]],
                          csp_header: Optional[str],
                          csp_report_only: Optional[str]) -> List[Dict]:
        """Analyze CSP for security issues."""
        findings = []

        # Check for unsafe directives
        for directive, values in parsed.items():
            values_str = ' '.join(values).lower()

            if "'unsafe-inline'" in values_str:
                findings.append({
                    "finding": f"unsafe-inline in {directive}",
                    "severity": "medium",
                    "description": f"The {directive} directive allows inline scripts/styles, reducing XSS protection."
                })

            if "'unsafe-eval'" in values_str:
                findings.append({
                    "finding": f"unsafe-eval in {directive}",
                    "severity": "high",
                    "description": f"The {directive} directive allows eval(), significantly weakening XSS protection."
                })

            # Check for overly permissive wildcards
            if '*' in values and directive in ['script-src', 'connect-src', 'frame-src']:
                findings.append({
                    "finding": f"Wildcard (*) in {directive}",
                    "severity": "high",
                    "description": f"The {directive} directive allows any source, effectively disabling CSP protection."
                })

        # Check for missing important directives
        important_directives = ['script-src', 'object-src', 'base-uri', 'frame-ancestors']
        for directive in important_directives:
            if directive not in parsed and 'default-src' not in parsed:
                findings.append({
                    "finding": f"Missing {directive} directive",
                    "severity": "low",
                    "description": f"The {directive} directive is not set and no default-src fallback exists."
                })

        # Check if only report-only mode
        if csp_report_only and not csp_header:
            findings.append({
                "finding": "CSP in Report-Only Mode",
                "severity": "info",
                "description": "CSP is configured but only in report-only mode, not enforcing restrictions."
            })

        # Check for deprecated directives
        deprecated = ['plugin-types', 'referrer']
        for directive in deprecated:
            if directive in parsed:
                findings.append({
                    "finding": f"Deprecated directive: {directive}",
                    "severity": "info",
                    "description": f"The {directive} directive is deprecated and should be removed."
                })

        return findings


def scan_multiple_domains(domains: List[str]) -> Dict[str, Any]:
    """
    Scan multiple domains and aggregate CSP data.
    Returns a consolidated list of external domains.
    """
    all_external_domains = set()
    all_potential_assets = []
    all_third_party = defaultdict(set)
    results_per_domain = []

    scanner = CSPScanner()

    for domain in domains:
        result = scanner.run_scan(domain)
        results_per_domain.append({
            "domain": domain,
            "external_count": len(result.get("external_domains", [])),
            "has_csp": result.get("statistics", {}).get("has_csp", False)
        })

        # Aggregate
        all_external_domains.update(result.get("external_domains", []))

        for asset in result.get("potential_assets", []):
            if asset not in all_potential_assets:
                all_potential_assets.append(asset)

        for category, domains_list in result.get("third_party_services", {}).items():
            all_third_party[category].update(domains_list)

    return {
        "total_domains_scanned": len(domains),
        "all_external_domains": sorted(list(all_external_domains)),
        "potential_company_assets": all_potential_assets,
        "third_party_services": {k: sorted(list(v)) for k, v in all_third_party.items()},
        "per_domain_results": results_per_domain,
        "statistics": {
            "unique_external_domains": len(all_external_domains),
            "potential_assets_count": len(all_potential_assets),
            "third_party_count": sum(len(v) for v in all_third_party.values())
        }
    }
