"""
Social Media Scanner
====================
Social media reconnaissance module.

Features:
- GitHub organization/repo discovery with secrets detection
- Twitter/X account verification and mentions
- YouTube channel discovery
- URL existence checking for LinkedIn/Facebook/Instagram (HEAD request only)
- Employee repo detection via email domain matching

Data Sources:
- GitHub API (BYOK github_token) - OPTIONAL
- Twitter/X API v2 (BYOK twitter_bearer_token) - OPTIONAL
- YouTube Data API v3 (uses existing google_api_key) - OPTIONAL
- LinkedIn/Facebook/Instagram (URL HEAD check only, no scraping) - ALWAYS
"""

import logging
import re
import base64
from typing import Any, Dict, List, Optional, Set
from datetime import datetime
from urllib.parse import quote

import requests
from sqlmodel import Session, select

from yads.core.base import BaseScannerModule
from yads.models import Tenant, Target
from yads.modules._shared_osint_utils import (
    SecretPatterns,
    SecretMatch,
    RateLimitedClient,
)


class SocialMediaScanner(BaseScannerModule):
    """
    Social Media Scanner for social media reconnaissance.
    """

    # Platform URL patterns for checking
    PLATFORM_PATTERNS = {
        "linkedin": "https://www.linkedin.com/company/{name}",
        "facebook": "https://www.facebook.com/{name}",
        "instagram": "https://www.instagram.com/{name}",
        "twitter": "https://twitter.com/{name}",
        "github": "https://github.com/{name}",
        "youtube": "https://www.youtube.com/@{name}",
    }

    def __init__(self, db_session: Session = None):
        super().__init__(db_session)
        self.logger = logging.getLogger("yads.modules.social_media_scanner")
        self.db_session = db_session

        # Initialize rate-limited HTTP client
        self.http = RateLimitedClient(default_timeout=15)
        self.http.register_service("github", requests_per_hour=5000)
        self.http.register_service("twitter", requests_per_minute=15)
        self.http.register_service("youtube", requests_per_minute=10)
        self.http.register_service("url_check", requests_per_second=2)

    @property
    def module_name(self) -> str:
        return "social_media_scanner"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute social media reconnaissance scan.
        """
        self.logger.info(f"Starting Social Media scan for: {target}")

        results = {
            "company_profiles": [],
            "code_exposure": [],
            "mentions": [],
            "url_checks": {},
            "status": "completed",
            "scanned_at": datetime.utcnow().isoformat()
        }

        # Get tenant context for BYOK APIs
        tenant = self._get_tenant(target)

        # Extract brand name from domain
        brand = target.rsplit('.', 1)[0] if '.' in target else target
        brand_clean = re.sub(r'[^a-zA-Z0-9]', '', brand)

        # 1. URL existence checks for various platforms (always runs)
        self.logger.info("Checking social media profile URLs...")
        results["url_checks"] = self._check_platform_urls(brand, brand_clean)

        # 2. GitHub scanning (if token configured)
        if tenant and tenant.github_token:
            self.logger.info("Scanning GitHub for organization/repos...")
            github_results = self._scan_github(target, brand, tenant.github_token)
            results["company_profiles"].extend(github_results.get("profiles", []))
            results["code_exposure"] = github_results.get("code_exposure", [])
        else:
            self.logger.info("Skipping GitHub: No token configured")

        # 3. Twitter/X scanning (if token configured)
        if tenant and tenant.twitter_bearer_token:
            self.logger.info("Scanning Twitter/X for mentions...")
            twitter_results = self._scan_twitter(brand, tenant.twitter_bearer_token)
            results["company_profiles"].extend(twitter_results.get("profiles", []))
            results["mentions"].extend(twitter_results.get("mentions", []))
        else:
            self.logger.info("Skipping Twitter/X: No bearer token configured")

        # 4. YouTube scanning (if Google API configured)
        if tenant and tenant.google_api_key:
            self.logger.info("Scanning YouTube for channels...")
            youtube_results = self._scan_youtube(brand, tenant.google_api_key)
            results["company_profiles"].extend(youtube_results)
        else:
            self.logger.info("Skipping YouTube: No Google API key configured")

        # Summary stats
        results["stats"] = {
            "profiles_found": len(results["company_profiles"]),
            "repos_with_secrets": sum(
                1 for r in results["code_exposure"]
                if r.get("contains_secrets")
            ),
            "total_secrets_found": sum(
                len(r.get("findings", [])) for r in results["code_exposure"]
            ),
            "mentions_found": len(results["mentions"]),
            "platforms_checked": list(results["url_checks"].keys())
        }

        self.logger.info(
            f"Social Media scan complete. "
            f"Found {results['stats']['profiles_found']} profiles, "
            f"{results['stats']['repos_with_secrets']} repos with secrets."
        )

        if target_id:
            from yads.models import OSINTIntelligence
            # Save Profiles
            for profile in results.get("company_profiles", []):
                self.db_session.add(OSINTIntelligence(
                    target_id=target_id, module_name=self.module_name,
                    data_type="social_profile", data_json=profile, severity="info"
                ))

            # Save Code Exposures / Secrets
            for exposure in results.get("code_exposure", []):
                if exposure.get("contains_secrets"):
                    # We can store the entire code exposure blob
                    self.db_session.add(OSINTIntelligence(
                        target_id=target_id, module_name=self.module_name,
                        data_type="code_exposure_leak", data_json=exposure, severity="high"
                    ))

            # Save Brand Mentions
            for mention in results.get("mentions", []):
                self.db_session.add(OSINTIntelligence(
                    target_id=target_id, module_name=self.module_name,
                    data_type="social_mention", data_json=mention, severity="info"
                ))

            self.db_session.commit()

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

    def _check_platform_urls(self, brand: str, brand_clean: str) -> Dict[str, Any]:
        """
        Check URL existence for various social media platforms.
        Uses HEAD requests only (ToS compliant).
        """
        url_checks = {}

        # Variations to try
        name_variations = [brand.lower(), brand_clean.lower()]

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 YADS/1.19"
        }

        for platform, url_pattern in self.PLATFORM_PATTERNS.items():
            # Skip platforms we're checking via API
            if platform in ["github", "twitter", "youtube"]:
                continue

            url_checks[platform] = {"exists": False, "url": None, "checked_urls": []}

            for name in name_variations:
                url = url_pattern.format(name=name)
                url_checks[platform]["checked_urls"].append(url)

                try:
                    # Use HEAD request for minimal footprint
                    response = self.http.head(
                        "url_check",
                        url,
                        headers=headers,
                        allow_redirects=True,
                        timeout=10
                    )

                    # 200 = exists, 404 = doesn't exist
                    if response.status_code == 200:
                        url_checks[platform]["exists"] = True
                        url_checks[platform]["url"] = url
                        break

                except Exception as e:
                    self.logger.debug(f"URL check failed for {url}: {e}")

        return url_checks

    def _scan_github(self, domain: str, brand: str, token: str) -> Dict[str, Any]:
        """
        Scan GitHub for organization, repos, and secrets.
        """
        results = {
            "profiles": [],
            "code_exposure": []
        }

        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }

        try:
            # 1. Search for organization
            org_url = f"https://api.github.com/orgs/{brand}"
            org_response = self.http.get("github", org_url, headers=headers)

            if org_response.status_code == 200:
                org_data = org_response.json()
                results["profiles"].append({
                    "platform": "github",
                    "type": "organization",
                    "url": org_data.get("html_url"),
                    "username": org_data.get("login"),
                    "verified": True,
                    "details": {
                        "name": org_data.get("name"),
                        "description": org_data.get("description"),
                        "public_repos": org_data.get("public_repos"),
                        "followers": org_data.get("followers")
                    }
                })

            # 2. Search for repositories mentioning the domain
            repos_url = f"https://api.github.com/search/repositories?q={quote(brand)}+OR+{quote(domain)}&per_page=10"
            repos_response = self.http.get("github", repos_url, headers=headers)

            if repos_response.status_code == 200:
                repos = repos_response.json().get("items", [])

                for repo in repos[:10]:
                    repo_info = {
                        "repo_url": repo.get("html_url"),
                        "repo_name": repo.get("full_name"),
                        "description": repo.get("description"),
                        "contains_secrets": False,
                        "findings": []
                    }

                    # Scan repo for secrets
                    secrets = self._scan_repo_for_secrets(repo, headers, domain)
                    if secrets:
                        repo_info["contains_secrets"] = True
                        repo_info["findings"] = secrets

                    results["code_exposure"].append(repo_info)

            # 3. Search code for domain emails
            code_url = f"https://api.github.com/search/code?q={quote(f'@{domain}')}+in:file&per_page=10"
            code_response = self.http.get("github", code_url, headers=headers)

            if code_response.status_code == 200:
                code_items = code_response.json().get("items", [])

                for item in code_items[:5]:
                    # Check if already in results
                    repo_url = item.get("repository", {}).get("html_url")
                    existing = next(
                        (r for r in results["code_exposure"] if r["repo_url"] == repo_url),
                        None
                    )

                    if not existing:
                        results["code_exposure"].append({
                            "repo_url": repo_url,
                            "repo_name": item.get("repository", {}).get("full_name"),
                            "file_path": item.get("path"),
                            "contains_secrets": False,
                            "findings": [],
                            "source": "email_mention"
                        })

        except Exception as e:
            self.logger.debug(f"GitHub scan failed: {e}")

        return results

    def _scan_repo_for_secrets(
        self,
        repo: Dict,
        headers: Dict,
        domain: str
    ) -> List[Dict[str, Any]]:
        """
        Scan a repository for exposed secrets.
        """
        findings = []

        try:
            # Get the default branch
            default_branch = repo.get("default_branch", "main")

            # Get repository tree
            tree_url = f"https://api.github.com/repos/{repo['full_name']}/git/trees/{default_branch}?recursive=1"
            tree_response = self.http.get("github", tree_url, headers=headers)

            if tree_response.status_code != 200:
                return findings

            tree = tree_response.json().get("tree", [])

            # Files to check for secrets
            sensitive_files = [
                f for f in tree
                if f["type"] == "blob" and self._is_sensitive_file(f["path"])
            ][:10]  # Limit to 10 files

            for file_entry in sensitive_files:
                try:
                    # Get file content
                    blob_url = f"https://api.github.com/repos/{repo['full_name']}/git/blobs/{file_entry['sha']}"
                    blob_response = self.http.get("github", blob_url, headers=headers)

                    if blob_response.status_code == 200:
                        blob_data = blob_response.json()
                        if blob_data.get("encoding") == "base64":
                            content = base64.b64decode(blob_data["content"]).decode("utf-8", errors="ignore")

                            # Scan for secrets
                            matches = SecretPatterns.scan_text(content, file_entry["path"])

                            for match in matches:
                                findings.append({
                                    "pattern_name": match.pattern_name,
                                    "file_path": match.file_path,
                                    "line_number": match.line_number,
                                    "severity": match.severity,
                                    "redacted_value": match.matched_text
                                })

                except Exception as e:
                    self.logger.debug(f"Failed to scan file {file_entry['path']}: {e}")

        except Exception as e:
            self.logger.debug(f"Failed to scan repo {repo['full_name']}: {e}")

        return findings

    def _is_sensitive_file(self, path: str) -> bool:
        """Check if a file is likely to contain secrets."""
        path_lower = path.lower()

        # File patterns that often contain secrets
        sensitive_patterns = [
            ".env",
            "config.json",
            "config.yaml",
            "config.yml",
            "settings.json",
            "settings.py",
            "credentials",
            ".npmrc",
            ".pypirc",
            "docker-compose",
            "application.properties",
            "application.yml",
            "secrets",
            ".htpasswd",
            "id_rsa",
            "id_dsa",
        ]

        for pattern in sensitive_patterns:
            if pattern in path_lower:
                return True

        return False

    def _scan_twitter(self, brand: str, bearer_token: str) -> Dict[str, Any]:
        """
        Scan Twitter/X for account and mentions.
        """
        results = {
            "profiles": [],
            "mentions": []
        }

        headers = {
            "Authorization": f"Bearer {bearer_token}"
        }

        try:
            # 1. Search for user account
            user_url = f"https://api.twitter.com/2/users/by/username/{brand}"
            user_response = self.http.get("twitter", user_url, headers=headers)

            if user_response.status_code == 200:
                user_data = user_response.json().get("data", {})
                if user_data:
                    results["profiles"].append({
                        "platform": "twitter",
                        "url": f"https://twitter.com/{user_data.get('username')}",
                        "username": user_data.get("username"),
                        "verified": True,
                        "details": {
                            "name": user_data.get("name"),
                            "id": user_data.get("id")
                        }
                    })

            # 2. Search for recent mentions
            search_url = f"https://api.twitter.com/2/tweets/search/recent?query={quote(brand)}&max_results=10"
            search_response = self.http.get("twitter", search_url, headers=headers)

            if search_response.status_code == 200:
                tweets = search_response.json().get("data", [])

                for tweet in tweets[:10]:
                    results["mentions"].append({
                        "platform": "twitter",
                        "url": f"https://twitter.com/i/web/status/{tweet.get('id')}",
                        "text_snippet": tweet.get("text", "")[:200],
                        "tweet_id": tweet.get("id")
                    })

        except Exception as e:
            self.logger.debug(f"Twitter scan failed: {e}")

        return results

    def _scan_youtube(self, brand: str, api_key: str) -> List[Dict[str, Any]]:
        """
        Scan YouTube for channels related to the brand.
        """
        profiles = []

        try:
            # Search for channels
            search_url = (
                f"https://www.googleapis.com/youtube/v3/search"
                f"?part=snippet&type=channel&q={quote(brand)}"
                f"&maxResults=5&key={api_key}"
            )
            response = self.http.get("youtube", search_url)

            if response.status_code == 200:
                items = response.json().get("items", [])

                for item in items:
                    snippet = item.get("snippet", {})
                    channel_id = item.get("id", {}).get("channelId")

                    if channel_id:
                        profiles.append({
                            "platform": "youtube",
                            "url": f"https://www.youtube.com/channel/{channel_id}",
                            "username": snippet.get("channelTitle"),
                            "verified": False,  # Would need additional API call to verify
                            "details": {
                                "title": snippet.get("title"),
                                "description": snippet.get("description", "")[:200],
                                "channel_id": channel_id
                            }
                        })

        except Exception as e:
            self.logger.debug(f"YouTube scan failed: {e}")

        return profiles
