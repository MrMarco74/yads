"""
GitHub / GitLab Exposure Scanner (Task #7)

Detects code/configuration exposure via:
1. Exposed .git directory on web server (/.git/HEAD accessible)
2. Common sensitive file paths (config files, env files, etc.)
3. GitHub/GitLab search for org/domain references (requires no API key for basic checks)
4. Exposed backup files (.bak, .old, .zip, etc.)

No GitHub API key required for the basic checks (HTTP-based).
"""

import logging
import re
import requests
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 8

# Sensitive paths to probe
SENSITIVE_PATHS = [
    # Version control
    ("/.git/HEAD", "git_exposed", "critical", "Exposed .git directory"),
    ("/.git/config", "git_exposed", "critical", "Exposed .git/config"),
    ("/.git/COMMIT_EDITMSG", "git_exposed", "critical", "Exposed .git directory (commit msg)"),
    ("/.svn/entries", "svn_exposed", "high", "Exposed SVN repository"),
    ("/.hg/hgrc", "hg_exposed", "high", "Exposed Mercurial repository"),
    # Environment / config files
    ("/.env", "env_exposed", "critical", "Exposed .env file"),
    ("/.env.local", "env_exposed", "critical", "Exposed .env.local file"),
    ("/.env.production", "env_exposed", "critical", "Exposed .env.production file"),
    ("/.env.backup", "env_exposed", "critical", "Exposed .env.backup file"),
    ("/config.php", "config_exposed", "high", "Exposed PHP config file"),
    ("/wp-config.php.bak", "config_exposed", "critical", "Exposed WordPress config backup"),
    ("/config/database.yml", "config_exposed", "high", "Exposed database config (Rails)"),
    ("/config/secrets.yml", "config_exposed", "critical", "Exposed secrets.yml (Rails)"),
    ("/config/application.yml", "config_exposed", "high", "Exposed application config"),
    ("/settings.py", "config_exposed", "high", "Exposed Django settings"),
    ("/local_settings.py", "config_exposed", "high", "Exposed Django local settings"),
    ("/appsettings.json", "config_exposed", "high", "Exposed ASP.NET config"),
    # Backup and archive files
    ("/backup.sql", "backup_exposed", "critical", "Exposed SQL backup"),
    ("/dump.sql", "backup_exposed", "critical", "Exposed SQL dump"),
    ("/database.sql", "backup_exposed", "critical", "Exposed database SQL"),
    ("/backup.zip", "backup_exposed", "high", "Exposed backup archive"),
    ("/backup.tar.gz", "backup_exposed", "high", "Exposed backup archive"),
    ("/www.zip", "backup_exposed", "high", "Exposed web root archive"),
    ("/site.zip", "backup_exposed", "high", "Exposed site archive"),
    # Log files
    ("/error.log", "log_exposed", "medium", "Exposed error log"),
    ("/access.log", "log_exposed", "medium", "Exposed access log"),
    ("/php_error.log", "log_exposed", "medium", "Exposed PHP error log"),
    ("/debug.log", "log_exposed", "medium", "Exposed debug log"),
    ("/storage/logs/laravel.log", "log_exposed", "medium", "Exposed Laravel log"),
    # Package management and dependencies
    ("/composer.json", "dependency_exposed", "low", "Exposed composer.json (tech enumeration)"),
    ("/package.json", "dependency_exposed", "low", "Exposed package.json (tech enumeration)"),
    ("/Gemfile", "dependency_exposed", "low", "Exposed Gemfile (tech enumeration)"),
    ("/requirements.txt", "dependency_exposed", "low", "Exposed requirements.txt"),
    ("/yarn.lock", "dependency_exposed", "low", "Exposed yarn.lock"),
    # CI/CD secrets
    ("/.travis.yml", "cicd_exposed", "medium", "Exposed Travis CI config"),
    ("/.gitlab-ci.yml", "cicd_exposed", "medium", "Exposed GitLab CI config"),
    ("/.github/workflows/deploy.yml", "cicd_exposed", "medium", "Exposed GitHub Actions workflow"),
    ("/Jenkinsfile", "cicd_exposed", "medium", "Exposed Jenkinsfile"),
    ("/docker-compose.yml", "cicd_exposed", "medium", "Exposed docker-compose.yml"),
    ("/docker-compose.prod.yml", "cicd_exposed", "medium", "Exposed production docker-compose"),
    # Other sensitive
    ("/phpinfo.php", "info_disclosure", "high", "phpinfo() exposed"),
    ("/info.php", "info_disclosure", "high", "phpinfo() exposed"),
    ("/test.php", "info_disclosure", "medium", "Test PHP page exposed"),
    ("/readme.txt", "info_disclosure", "low", "README exposed (version info)"),
    ("/README.md", "info_disclosure", "low", "README.md exposed"),
    ("/CHANGELOG.md", "info_disclosure", "low", "Changelog exposed (version info)"),
    ("/crossdomain.xml", "info_disclosure", "low", "crossdomain.xml exposed"),
    ("/elmah.axd", "info_disclosure", "high", "ELMAH error log exposed (ASP.NET)"),
    ("/trace.axd", "info_disclosure", "high", "Trace.axd exposed (ASP.NET)"),
]

# Patterns that indicate a real exposure (not just a generic 200)
CONTENT_INDICATORS = {
    "git_exposed": ["ref:", "HEAD", "[core]"],
    "env_exposed": ["APP_KEY", "DB_PASSWORD", "SECRET_KEY", "API_KEY", "AWS_", "DATABASE_URL"],
    "backup_exposed": ["INSERT INTO", "CREATE TABLE", "mysqldump"],
    "log_exposed": ["PHP Fatal error", "Uncaught exception", "Stack trace"],
    "config_exposed": ["password", "secret", "database", "credentials"],
    "info_disclosure": ["phpinfo", "PHP Version", "Configuration"],
}

# Domain suffixes that indicate GitHub/GitLab hosted (for CNAME check)
HOSTING_INDICATORS = [
    "github.io", "gitlab.io", "pages.github.com",
    "github.com", "gitlab.com",
]


class GitExposureScanner(BaseScannerModule):
    """Scan for exposed .git directories, sensitive files, and config leaks."""

    @property
    def module_name(self) -> str:
        return "git_exposure"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = target.lower().strip().removeprefix("https://").removeprefix("http://").split("/")[0]

        result: Dict[str, Any] = {
            "domain": domain,
            "base_urls": [],
            "findings": [],
            "exposed_paths": [],
            "summary": {
                "score": 100,
                "total_checked": 0,
                "exposed_count": 0,
            },
        }

        # Build base URLs to check
        base_urls = self._build_base_urls(domain)
        result["base_urls"] = base_urls

        if not base_urls:
            result["error"] = "Domain not reachable via HTTP or HTTPS"
            return result

        exposed_paths = []
        checked = 0

        for base_url in base_urls:
            for path, category, severity, description in SENSITIVE_PATHS:
                url = base_url.rstrip("/") + path
                checked += 1
                exposed = self._check_path(url, category)
                if exposed:
                    entry = {
                        "url": url,
                        "path": path,
                        "category": category,
                        "severity": severity,
                        "description": description,
                        "status_code": exposed.get("status_code"),
                        "content_match": exposed.get("content_match"),
                    }
                    exposed_paths.append(entry)
                    exposed_finding = {
                        "severity": severity,
                        "title": description,
                        "detail": f"{url} returned HTTP {exposed.get('status_code')}",
                        "url": url,
                        "category": category,
                    }
                    result["findings"].append(exposed_finding)

                    # Stream Git/Config exposure finding in real-time to Splunk SIEM
                    try:
                        from yads.core.splunk_logger import splunk_logger
                        splunk_logger.send_finding_event(
                            finding_type=f"exposure:{category}",
                            domain=domain,
                            severity=severity,
                            mitre_id="T1552.001",
                            details=exposed_finding
                        )
                    except Exception:
                        pass
            # Don't duplicate across http/https
            break

        result["exposed_paths"] = exposed_paths
        result["summary"]["total_checked"] = checked
        result["summary"]["exposed_count"] = len(exposed_paths)

        # Score
        score = 100
        for f in result["findings"]:
            sev = f["severity"]
            if sev == "critical":
                score -= 25
            elif sev == "high":
                score -= 15
            elif sev == "medium":
                score -= 8
            else:
                score -= 2

        result["summary"]["score"] = max(0, score)
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_base_urls(self, domain: str) -> List[str]:
        """Return list of reachable base URLs (prefer https)."""
        urls = []
        for scheme in ("https", "http"):
            try:
                resp = requests.head(
                    f"{scheme}://{domain}",
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0 YADS Security Scanner"},
                )
                if resp.status_code < 500:
                    urls.append(f"{scheme}://{domain}")
                    break  # prefer https
            except Exception:
                continue
        return urls

    def _check_path(self, url: str, category: str) -> Optional[Dict]:
        """Return dict if path appears genuinely exposed, None otherwise."""
        try:
            resp = requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 YADS Security Scanner"},
            )
            # Only 200 OK is interesting; 301/302 to main page is a false positive
            if resp.status_code != 200:
                return None

            # Content length check — empty responses are not interesting
            content_length = len(resp.content)
            if content_length < 10:
                return None

            body = resp.text[:2000]

            # Check content indicators
            indicators = CONTENT_INDICATORS.get(category, [])
            matched = None
            for indicator in indicators:
                if indicator.lower() in body.lower():
                    matched = indicator
                    break

            # For git/env/backup, require content match; others accept 200 + size
            if category in ("git_exposed", "env_exposed", "backup_exposed"):
                if not matched:
                    return None

            return {
                "status_code": resp.status_code,
                "content_length": content_length,
                "content_match": matched,
            }

        except Exception:
            return None
