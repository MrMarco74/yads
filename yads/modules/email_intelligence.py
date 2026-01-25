"""
Email Intelligence Scanner
==========================
Email discovery and breach analysis module.

Features:
- Email discovery via Hunter.io API (optional BYOK)
- Email pattern analysis (firstname.lastname@, f.lastname@, etc.)
- GitHub commit email extraction
- HIBP breach checking (extends existing leak_monitor.py)
- Website scraping for emails
- Cross-reference with crawler results

Data Sources:
- Hunter.io (BYOK, free: 25/month, paid: $49/month) - OPTIONAL
- HIBP (BYOK, $3.50/month) - OPTIONAL
- GitHub Search (optional github_token) - OPTIONAL
- Website scraping (free) - ALWAYS
- Pattern generation (free) - ALWAYS
"""

import logging
import re
import time
import concurrent.futures
from typing import Any, Dict, List, Optional, Set
from datetime import datetime

import requests
from bs4 import BeautifulSoup
from sqlmodel import Session, select

from yads.core.base import BaseScannerModule
from yads.models import Tenant, Target, ScanResult
from yads.modules._shared_osint_utils import (
    EmailPatternDetector,
    OSINTQuotaManager,
    RateLimitedClient,
)


class EmailIntelligenceScanner(BaseScannerModule):
    """
    Email Intelligence Scanner for email discovery and breach analysis.
    """

    # Common email patterns to check
    COMMON_ALIASES = [
        "info", "admin", "support", "contact", "sales", "help",
        "security", "abuse", "webmaster", "postmaster", "noreply",
        "hr", "jobs", "careers", "press", "media", "marketing"
    ]

    # Email regex pattern
    EMAIL_REGEX = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    )

    def __init__(self, db_session: Session = None):
        super().__init__(db_session)
        self.logger = logging.getLogger("yads.modules.email_intelligence")
        self.db_session = db_session

        # Initialize rate-limited HTTP client
        self.http = RateLimitedClient(default_timeout=15)
        self.http.register_service("hunter", requests_per_minute=10)
        self.http.register_service("hibp", requests_per_second=0.6)  # 1 req / 1.6s
        self.http.register_service("github", requests_per_hour=5000)
        self.http.register_service("web", requests_per_second=2)

    @property
    def module_name(self) -> str:
        return "email_intelligence"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute email intelligence scan.
        """
        self.logger.info(f"Starting Email Intelligence scan for: {target}")

        results = {
            "discovered_emails": [],
            "email_patterns": [],
            "breach_exposure": [],
            "domain_info": {
                "mx_records": [],
                "has_catch_all": None,
                "email_provider": None
            },
            "status": "completed",
            "scanned_at": datetime.utcnow().isoformat()
        }

        # Get tenant context for BYOK APIs
        tenant = self._get_tenant(target)
        all_emails: Set[str] = set()

        # 1. Get MX records and domain info
        self.logger.info("Fetching MX records...")
        results["domain_info"] = self._get_domain_info(target)

        # 2. Discover emails from Hunter.io (if configured)
        if tenant and tenant.hunter_api_key:
            self.logger.info("Searching Hunter.io for emails...")
            hunter_emails = self._search_hunter(target, tenant.hunter_api_key)
            all_emails.update(hunter_emails)
            for email in hunter_emails:
                results["discovered_emails"].append({
                    "email": email,
                    "source": "hunter.io",
                    "confidence": "high",
                    "role": self._guess_role(email)
                })
        else:
            self.logger.info("Skipping Hunter.io: No API key configured")

        # 3. Discover emails from GitHub (if configured)
        if tenant and tenant.github_token:
            self.logger.info("Searching GitHub for commit emails...")
            github_emails = self._search_github_emails(target, tenant.github_token)
            for email in github_emails:
                if email not in all_emails:
                    all_emails.add(email)
                    results["discovered_emails"].append({
                        "email": email,
                        "source": "github_commits",
                        "confidence": "medium",
                        "role": self._guess_role(email)
                    })
        else:
            self.logger.info("Skipping GitHub: No token configured")

        # 4. Scrape website for emails (always runs)
        self.logger.info("Scraping website for emails...")
        web_emails = self._scrape_website_emails(target)
        for email in web_emails:
            if email not in all_emails:
                all_emails.add(email)
                results["discovered_emails"].append({
                    "email": email,
                    "source": "website_scrape",
                    "confidence": "high",
                    "role": self._guess_role(email)
                })

        # 5. Check previous crawler results for emails
        if target_id:
            self.logger.info("Checking crawler results for emails...")
            crawler_emails = self._extract_from_crawler(target_id)
            for email in crawler_emails:
                if email not in all_emails:
                    all_emails.add(email)
                    results["discovered_emails"].append({
                        "email": email,
                        "source": "crawler",
                        "confidence": "high",
                        "role": self._guess_role(email)
                    })

        # 6. Generate common aliases
        self.logger.info("Generating common email aliases...")
        aliases = self._generate_common_aliases(target)
        for email in aliases:
            if email not in all_emails:
                all_emails.add(email)
                results["discovered_emails"].append({
                    "email": email,
                    "source": "pattern_generation",
                    "confidence": "low",
                    "role": self._guess_role(email)
                })

        # 7. Detect email patterns
        domain_emails = [e for e in all_emails if e.endswith(f"@{target}")]
        if domain_emails:
            pattern = EmailPatternDetector.detect_pattern(domain_emails, target)
            if pattern:
                results["email_patterns"].append(pattern)

        # 8. Check breaches via HIBP (if configured)
        if tenant and tenant.hibp_api_key:
            self.logger.info("Checking emails against HIBP...")
            # Only check high-confidence emails to avoid wasting API calls
            high_conf_emails = [
                e["email"] for e in results["discovered_emails"]
                if e["confidence"] in ["high", "medium"]
            ][:20]  # Limit to 20 emails

            breach_results = self._check_hibp_breaches(high_conf_emails, tenant.hibp_api_key)
            results["breach_exposure"] = breach_results
        else:
            self.logger.info("Skipping HIBP: No API key configured")

        # Summary stats
        results["stats"] = {
            "total_emails": len(results["discovered_emails"]),
            "unique_domains": len(set(e["email"].split("@")[1] for e in results["discovered_emails"] if "@" in e["email"])),
            "breached_emails": sum(1 for b in results["breach_exposure"] if b.get("breach_count", 0) > 0),
            "sources_used": list(set(e["source"] for e in results["discovered_emails"]))
        }

        self.logger.info(
            f"Email Intelligence scan complete. "
            f"Found {results['stats']['total_emails']} emails, "
            f"{results['stats']['breached_emails']} with breaches."
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

    def _get_domain_info(self, domain: str) -> Dict[str, Any]:
        """Get MX records and email provider info."""
        import dns.resolver

        info = {
            "mx_records": [],
            "has_catch_all": None,
            "email_provider": None
        }

        try:
            # Get MX records
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in answers:
                mx_host = str(rdata.exchange).rstrip('.')
                info["mx_records"].append({
                    "host": mx_host,
                    "priority": rdata.preference
                })

            # Detect email provider from MX records
            mx_hosts = [mx["host"].lower() for mx in info["mx_records"]]
            mx_text = " ".join(mx_hosts)

            if "google" in mx_text or "gmail" in mx_text:
                info["email_provider"] = "Google Workspace"
            elif "outlook" in mx_text or "microsoft" in mx_text:
                info["email_provider"] = "Microsoft 365"
            elif "zoho" in mx_text:
                info["email_provider"] = "Zoho Mail"
            elif "protonmail" in mx_text:
                info["email_provider"] = "ProtonMail"
            elif "mimecast" in mx_text:
                info["email_provider"] = "Mimecast"
            elif "barracuda" in mx_text:
                info["email_provider"] = "Barracuda"

        except Exception as e:
            self.logger.debug(f"Failed to get MX records: {e}")

        return info

    def _search_hunter(self, domain: str, api_key: str) -> Set[str]:
        """Search Hunter.io for emails."""
        emails = set()

        try:
            url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
            response = self.http.get("hunter", url)

            if response.status_code == 200:
                data = response.json()

                if data.get("data", {}).get("emails"):
                    for email_entry in data["data"]["emails"]:
                        email = email_entry.get("value")
                        if email:
                            emails.add(email.lower())

                    self.logger.info(f"Hunter.io found {len(emails)} emails")

            elif response.status_code == 401:
                self.logger.warning("Hunter.io: Invalid API key")
            elif response.status_code == 429:
                self.logger.warning("Hunter.io: Rate limit exceeded")

        except Exception as e:
            self.logger.debug(f"Hunter.io search failed: {e}")

        return emails

    def _search_github_emails(self, domain: str, token: str) -> Set[str]:
        """Search GitHub for commit emails related to the domain."""
        emails = set()

        try:
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json"
            }

            # Search for repositories related to the domain
            search_url = f"https://api.github.com/search/repositories?q={domain}&per_page=5"
            response = self.http.get("github", search_url, headers=headers)

            if response.status_code == 200:
                repos = response.json().get("items", [])

                for repo in repos[:5]:  # Limit to 5 repos
                    # Get recent commits
                    commits_url = f"https://api.github.com/repos/{repo['full_name']}/commits?per_page=30"
                    commits_resp = self.http.get("github", commits_url, headers=headers)

                    if commits_resp.status_code == 200:
                        commits = commits_resp.json()

                        for commit in commits:
                            if commit.get("commit", {}).get("author", {}).get("email"):
                                email = commit["commit"]["author"]["email"].lower()
                                # Filter to domain emails only
                                if email.endswith(f"@{domain}"):
                                    emails.add(email)

            # Also search code for email patterns
            code_search_url = f"https://api.github.com/search/code?q={domain}+in:file&per_page=10"
            code_resp = self.http.get("github", code_search_url, headers=headers)

            if code_resp.status_code == 200:
                items = code_resp.json().get("items", [])
                for item in items[:5]:
                    # Get file content
                    try:
                        file_resp = self.http.get("github", item["url"], headers=headers)
                        if file_resp.status_code == 200:
                            content = file_resp.json().get("content", "")
                            if content:
                                import base64
                                decoded = base64.b64decode(content).decode("utf-8", errors="ignore")
                                found = self.EMAIL_REGEX.findall(decoded)
                                for email in found:
                                    if email.endswith(f"@{domain}"):
                                        emails.add(email.lower())
                    except Exception:
                        pass

            self.logger.info(f"GitHub found {len(emails)} domain emails")

        except Exception as e:
            self.logger.debug(f"GitHub search failed: {e}")

        return emails

    def _scrape_website_emails(self, domain: str) -> Set[str]:
        """Scrape the website for email addresses."""
        emails = set()
        pages_to_check = [
            f"https://{domain}",
            f"https://{domain}/contact",
            f"https://{domain}/about",
            f"https://{domain}/impressum",
            f"https://{domain}/imprint",
            f"https://{domain}/kontakt",
            f"https://www.{domain}",
        ]

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        for url in pages_to_check:
            try:
                response = self.http.get("web", url, headers=headers, timeout=10)

                if response.status_code == 200:
                    # Extract from HTML
                    soup = BeautifulSoup(response.text, 'html.parser')

                    # Get text content
                    text = soup.get_text()
                    found = self.EMAIL_REGEX.findall(text)
                    emails.update(e.lower() for e in found)

                    # Check href attributes
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        if href.startswith('mailto:'):
                            email = href.replace('mailto:', '').split('?')[0]
                            if '@' in email:
                                emails.add(email.lower())

            except Exception as e:
                self.logger.debug(f"Failed to scrape {url}: {e}")

        # Filter to target domain only
        domain_emails = {e for e in emails if e.endswith(f"@{domain}")}

        self.logger.info(f"Website scrape found {len(domain_emails)} domain emails")
        return domain_emails

    def _extract_from_crawler(self, target_id: int) -> Set[str]:
        """Extract emails from previous crawler results."""
        emails = set()

        if not self.db_session:
            return emails

        try:
            # Get latest crawler result
            crawler_result = self.db_session.exec(
                select(ScanResult)
                .where(ScanResult.target_id == target_id)
                .where(ScanResult.module_name == "crawler")
                .order_by(ScanResult.scanned_at.desc())
            ).first()

            if crawler_result and crawler_result.data:
                # Extract URLs that might contain emails
                crawled_urls = crawler_result.data.get("crawled_urls", [])

                for url_entry in crawled_urls:
                    body = url_entry.get("body_text", "") or url_entry.get("snippet", "")
                    if body:
                        found = self.EMAIL_REGEX.findall(body)
                        emails.update(e.lower() for e in found)

        except Exception as e:
            self.logger.debug(f"Failed to extract from crawler: {e}")

        return emails

    def _generate_common_aliases(self, domain: str) -> Set[str]:
        """Generate common email aliases for the domain."""
        emails = set()

        for alias in self.COMMON_ALIASES:
            emails.add(f"{alias}@{domain}")

        return emails

    def _guess_role(self, email: str) -> Optional[str]:
        """Guess the role/department from email address."""
        local_part = email.split("@")[0].lower()

        role_mapping = {
            "info": "general",
            "admin": "admin",
            "support": "support",
            "sales": "sales",
            "hr": "hr",
            "jobs": "hr",
            "careers": "hr",
            "security": "security",
            "abuse": "security",
            "press": "marketing",
            "media": "marketing",
            "marketing": "marketing",
            "ceo": "executive",
            "cto": "executive",
            "cfo": "executive",
            "dev": "engineering",
            "engineering": "engineering",
            "legal": "legal",
        }

        for keyword, role in role_mapping.items():
            if keyword in local_part:
                return role

        return None

    def _check_hibp_breaches(self, emails: List[str], api_key: str) -> List[Dict[str, Any]]:
        """Check emails against Have I Been Pwned."""
        results = []
        headers = {
            "hibp-api-key": api_key,
            "user-agent": "YADS-Security-Scanner-v1.15"
        }

        for email in emails:
            try:
                url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
                response = self.http.get("hibp", url, headers=headers)

                if response.status_code == 200:
                    breaches = response.json()
                    breach_names = [b["Name"] for b in breaches]

                    results.append({
                        "email": email,
                        "breaches": breach_names,
                        "breach_count": len(breach_names),
                        "breached": True
                    })

                    self.logger.warning(f"BREACH FOUND: {email} in {len(breach_names)} breaches")

                elif response.status_code == 404:
                    # No breaches found
                    results.append({
                        "email": email,
                        "breaches": [],
                        "breach_count": 0,
                        "breached": False
                    })

                elif response.status_code == 429:
                    self.logger.warning("HIBP rate limit exceeded")
                    break

            except Exception as e:
                self.logger.debug(f"HIBP check failed for {email}: {e}")

        return results
