"""
Brand Intelligence Scanner
==========================
Enhanced OSINT and brand monitoring module.

Features:
- Extended lookalike domain detection (homoglyphs, bitsquatting, combosquatting)
- PhishTank/URLhaus integration for phishing detection
- Brand mentions via Google Custom Search (BYOK)
- Reputation scoring

Data Sources:
- PhishTank API (public, free)
- URLhaus API (public, free)
- Google Custom Search (BYOK, ~$5/1000 queries)
- Local variation generation (free)
"""

import logging
import concurrent.futures
from typing import Any, Dict, List, Optional
from datetime import datetime

import dns.resolver
import requests
from sqlmodel import Session, select

from yads.core.base import BaseScannerModule
from yads.models import Tenant, Target
from yads.modules._shared_osint_utils import (
    DomainVariationGenerator,
    OSINTQuotaManager,
    RateLimitedClient,
)


class BrandIntelligenceScanner(BaseScannerModule):
    """
    Brand Intelligence Scanner for enhanced OSINT and brand monitoring.
    """

    def __init__(self, db_session: Session = None):
        super().__init__(db_session)
        self.logger = logging.getLogger("yads.modules.brand_intelligence")
        self.db_session = db_session

        # Initialize rate-limited HTTP client
        self.http = RateLimitedClient(default_timeout=15)
        self.http.register_service("phishtank", requests_per_minute=30)
        self.http.register_service("urlhaus", requests_per_minute=60)
        self.http.register_service("google", requests_per_minute=10)

        # DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2.0
        self.resolver.lifetime = 2.0

    @property
    def module_name(self) -> str:
        return "brand_intelligence"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute brand intelligence scan.
        """
        self.logger.info(f"Starting Brand Intelligence scan for: {target}")

        results = {
            "lookalike_domains": [],
            "phishing_indicators": [],
            "brand_mentions": [],
            "reputation_score": {"overall": 100, "factors": {}},
            "status": "completed",
            "scanned_at": datetime.utcnow().isoformat()
        }

        # Get tenant context for BYOK APIs
        tenant = self._get_tenant(target)
        quota_mgr = None
        if tenant:
            quota_mgr = OSINTQuotaManager(self.db_session, tenant.id)

        # 1. Generate and check lookalike domains
        self.logger.info("Generating domain variations...")
        lookalike_results = self._scan_lookalike_domains(target)
        results["lookalike_domains"] = lookalike_results

        # 2. Check PhishTank for reported phishing
        self.logger.info("Checking PhishTank...")
        phishtank_results = self._check_phishtank(target)
        results["phishing_indicators"].extend(phishtank_results)

        # 3. Check URLhaus for malicious URLs
        self.logger.info("Checking URLhaus...")
        urlhaus_results = self._check_urlhaus(target)
        results["phishing_indicators"].extend(urlhaus_results)

        # 4. Brand mentions via Google Search (if BYOK configured)
        if tenant and tenant.google_api_key and tenant.google_cse_cx:
            if quota_mgr and quota_mgr.can_use(cost=1):
                self.logger.info("Searching for brand mentions...")
                mentions = self._search_brand_mentions(target, tenant)
                results["brand_mentions"] = mentions
                quota_mgr.consume(cost=1)
            else:
                self.logger.info("Skipping brand mentions: OSINT quota exceeded")
                results["brand_mentions_skipped"] = "quota_exceeded"
        else:
            self.logger.info("Skipping brand mentions: No Google API key configured")
            results["brand_mentions_skipped"] = "no_api_key"

        # 5. Calculate reputation score
        results["reputation_score"] = self._calculate_reputation(results)

        # Summary stats
        results["stats"] = {
            "lookalike_count": len(results["lookalike_domains"]),
            "high_risk_lookalikes": sum(
                1 for d in results["lookalike_domains"]
                if d.get("risk_level") == "high"
            ),
            "phishing_indicators": len(results["phishing_indicators"]),
            "brand_mentions": len(results["brand_mentions"])
        }

        self.logger.info(
            f"Brand Intelligence scan complete. "
            f"Found {results['stats']['lookalike_count']} lookalikes, "
            f"{results['stats']['phishing_indicators']} phishing indicators."
        )

        return results

    def _get_tenant(self, domain: str) -> Optional[Tenant]:
        """Get tenant for the target domain."""
        if not self.db_session:
            return None

        target_obj = self.db_session.exec(
            select(Target).where(Target.domain == domain)
        ).first()

        if not target_obj or not target_obj.tenant_id:
            return None

        return self.db_session.get(Tenant, target_obj.tenant_id)

    def _scan_lookalike_domains(self, domain: str) -> List[Dict[str, Any]]:
        """
        Generate and scan lookalike domain variations.
        """
        found_domains = []

        # Generate variations using all methods
        variations = DomainVariationGenerator.generate_all_variations(
            domain,
            include_homoglyphs=True,
            include_bitsquats=True,
            include_combosquats=True,
            max_total=300
        )

        self.logger.info(f"Generated {len(variations)} domain variations to check")

        def check_domain(variant: str) -> Optional[Dict]:
            """Check if a domain variant resolves."""
            try:
                answers = self.resolver.resolve(variant, 'A')
                ips = [r.to_text() for r in answers]

                # Determine similarity type
                similarity_type = self._classify_variation(domain, variant)

                # Risk assessment
                risk_level = self._assess_risk(domain, variant, ips)

                return {
                    "domain": variant,
                    "ips": ips,
                    "similarity_type": similarity_type,
                    "risk_level": risk_level,
                    "resolved": True
                }
            except Exception:
                return None

        # Parallel DNS checks
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_domain, var): var for var in variations}

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found_domains.append(result)

        # Sort by risk level
        risk_order = {"high": 0, "medium": 1, "low": 2}
        found_domains.sort(key=lambda x: risk_order.get(x.get("risk_level", "low"), 3))

        return found_domains

    def _classify_variation(self, original: str, variant: str) -> str:
        """Classify the type of domain variation."""
        orig_name = original.rsplit('.', 1)[0] if '.' in original else original
        var_name = variant.rsplit('.', 1)[0] if '.' in variant else variant

        # Check for prefix/suffix (combosquat)
        if var_name.startswith(orig_name + '-') or var_name.startswith(orig_name + '_'):
            return "combosquat_suffix"
        if var_name.endswith('-' + orig_name) or var_name.endswith('_' + orig_name):
            return "combosquat_prefix"
        if orig_name in var_name and var_name != orig_name:
            return "combosquat"

        # Check edit distance for typos
        if len(orig_name) == len(var_name):
            diff_count = sum(1 for a, b in zip(orig_name, var_name) if a != b)
            if diff_count == 1:
                return "typosquat"
            if diff_count == 2:
                return "bitsquat"

        if abs(len(orig_name) - len(var_name)) == 1:
            return "typosquat"

        # Check TLD only difference
        if orig_name == var_name:
            return "tld_swap"

        return "homoglyph"

    def _assess_risk(self, original: str, variant: str, ips: List[str]) -> str:
        """Assess the risk level of a lookalike domain."""
        # High risk indicators
        high_risk_keywords = ['login', 'signin', 'secure', 'account', 'verify', 'auth']
        for keyword in high_risk_keywords:
            if keyword in variant.lower():
                return "high"

        # Check if domain is very similar (1 char diff)
        orig_name = original.rsplit('.', 1)[0]
        var_name = variant.rsplit('.', 1)[0]

        if len(orig_name) == len(var_name):
            diff_count = sum(1 for a, b in zip(orig_name, var_name) if a != b)
            if diff_count == 1:
                return "high"

        # Medium risk for resolved domains
        if ips:
            return "medium"

        return "low"

    def _check_phishtank(self, domain: str) -> List[Dict[str, Any]]:
        """
        Check PhishTank for phishing reports related to the domain.
        Note: PhishTank requires API key for lookups, using public data feed check.
        """
        indicators = []

        try:
            # PhishTank check URL (simplified - real implementation would use API)
            # We're checking if domain appears in recent phishing reports
            url = f"https://checkurl.phishtank.com/checkurl/?url=http://{domain}"

            # Note: Real implementation would use proper API with key
            # This is a placeholder showing the integration pattern
            response = self.http.get("phishtank", url, allow_redirects=False)

            # PhishTank returns specific status codes for known phishing
            if response.status_code == 200:
                # Parse response for phishing status
                # In real implementation, would parse the XML/JSON response
                pass

        except Exception as e:
            self.logger.debug(f"PhishTank check failed: {e}")

        return indicators

    def _check_urlhaus(self, domain: str) -> List[Dict[str, Any]]:
        """
        Check URLhaus for malicious URLs associated with the domain.
        """
        indicators = []

        try:
            # URLhaus API endpoint
            url = "https://urlhaus-api.abuse.ch/v1/host/"

            response = self.http.post(
                "urlhaus",
                url,
                data={"host": domain},
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )

            if response.status_code == 200:
                data = response.json()

                if data.get("query_status") == "ok" and data.get("urls"):
                    for url_entry in data.get("urls", [])[:10]:  # Limit to 10
                        indicators.append({
                            "domain": domain,
                            "source": "urlhaus",
                            "url": url_entry.get("url", ""),
                            "threat": url_entry.get("threat", "unknown"),
                            "reported_at": url_entry.get("date_added", ""),
                            "status": url_entry.get("url_status", "")
                        })

                    self.logger.warning(
                        f"URLhaus: Found {len(data.get('urls', []))} malicious URLs for {domain}"
                    )

        except Exception as e:
            self.logger.debug(f"URLhaus check failed: {e}")

        return indicators

    def _search_brand_mentions(self, domain: str, tenant: Tenant) -> List[Dict[str, Any]]:
        """
        Search for brand mentions using Google Custom Search.
        """
        mentions = []

        if not tenant.google_api_key or not tenant.google_cse_cx:
            return mentions

        try:
            # Extract brand name from domain
            brand = domain.rsplit('.', 1)[0] if '.' in domain else domain

            # Search queries to run
            queries = [
                f'"{brand}" scam OR phishing',
                f'"{brand}" fake OR fraud',
                f'site:reddit.com "{brand}"',
            ]

            for query in queries[:2]:  # Limit API usage
                url = (
                    f"https://www.googleapis.com/customsearch/v1"
                    f"?key={tenant.google_api_key}"
                    f"&cx={tenant.google_cse_cx}"
                    f"&q={query}"
                    f"&num=5"
                )

                response = self.http.get("google", url)

                if response.status_code == 200:
                    data = response.json()

                    for item in data.get("items", []):
                        mentions.append({
                            "source": "google_search",
                            "url": item.get("link", ""),
                            "title": item.get("title", ""),
                            "context": item.get("snippet", "")[:200],
                            "query": query
                        })

        except Exception as e:
            self.logger.debug(f"Google search failed: {e}")

        return mentions

    def _calculate_reputation(self, results: Dict) -> Dict[str, Any]:
        """
        Calculate overall reputation score based on findings.
        """
        score = 100
        factors = {}

        # Deduct for high-risk lookalikes
        high_risk_count = sum(
            1 for d in results.get("lookalike_domains", [])
            if d.get("risk_level") == "high"
        )
        if high_risk_count > 0:
            deduction = min(30, high_risk_count * 5)
            score -= deduction
            factors["high_risk_lookalikes"] = {
                "count": high_risk_count,
                "deduction": deduction,
                "severity": "high" if high_risk_count > 3 else "medium"
            }

        # Deduct for phishing indicators
        phishing_count = len(results.get("phishing_indicators", []))
        if phishing_count > 0:
            deduction = min(40, phishing_count * 10)
            score -= deduction
            factors["phishing_indicators"] = {
                "count": phishing_count,
                "deduction": deduction,
                "severity": "critical" if phishing_count > 2 else "high"
            }

        # Deduct for any lookalike domains
        lookalike_count = len(results.get("lookalike_domains", []))
        if lookalike_count > 10:
            deduction = min(20, (lookalike_count - 10) // 5 * 2)
            score -= deduction
            factors["excessive_lookalikes"] = {
                "count": lookalike_count,
                "deduction": deduction,
                "severity": "medium"
            }

        # Ensure score doesn't go below 0
        score = max(0, score)

        # Determine grade
        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        return {
            "overall": score,
            "grade": grade,
            "factors": factors
        }
