"""
Wayback Machine Secrets Scanner (Task #18)

Queries the Internet Archive CDX API for historically captured URLs
and identifies sensitive historical exposures: config files, backups,
.env files, API keys in query params, old admin paths, and more.

Uses the free Wayback CDX API — no API key required.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Set

import requests

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

CDX_API = "https://web.archive.org/cdx/search/cdx"
REQUEST_TIMEOUT = 20

# (regex_pattern, severity, category, description)
SENSITIVE_URL_PATTERNS = [
    (r"\.env($|\?|&|#)", "critical", "env_file", ".env file captured in Wayback Machine"),
    (r"\.env\.(local|production|staging|backup|old)($|\?)", "critical", "env_file", ".env variant captured"),
    (r"wp-config\.php", "critical", "config_file", "WordPress config file captured"),
    (r"config\.php($|\?)", "high", "config_file", "PHP config file captured"),
    (r"database\.yml($|\?)", "high", "config_file", "Database config (Rails) captured"),
    (r"secrets\.yml($|\?)", "critical", "config_file", "Rails secrets.yml captured"),
    (r"application\.yml($|\?)", "high", "config_file", "Application config captured"),
    (r"appsettings\.json($|\?)", "high", "config_file", "ASP.NET appsettings captured"),
    (r"local_settings\.py($|\?)", "high", "config_file", "Django local settings captured"),
    (r"\.(sql|dump)($|\?)", "critical", "backup", "SQL backup/dump captured"),
    (r"backup\.(zip|tar\.gz|tar|gz)($|\?)", "high", "archive", "Backup archive captured"),
    (r"www\.(zip|tar\.gz)($|\?)", "high", "archive", "Web root archive captured"),
    (r"\.(log|err)($|\?)", "medium", "log_file", "Log file captured"),
    (r"/\.git/", "critical", "vcs", ".git directory captured"),
    (r"/\.svn/", "high", "vcs", ".svn directory captured"),
    (r"phpinfo\.php", "high", "info_disclosure", "phpinfo() captured"),
    (r"info\.php($|\?)", "high", "info_disclosure", "PHP info page captured"),
    (r"[?&](api[_\-]?key|apikey|access[_\-]?token|secret|token|key)=[^&\s]{8,}", "high", "api_key_param", "API key/token in URL parameters"),
    (r"[?&](aws[_\-]?key|aws[_\-]?secret|aws[_\-]?access)=[^&\s]+", "critical", "aws_key_param", "AWS credentials in URL"),
    (r"/phpmyadmin", "high", "admin", "phpMyAdmin captured"),
    (r"/(staging|test|dev|debug|beta)($|/)", "low", "dev_path", "Dev/staging path captured"),
    (r"/(admin|administrator)($|/)", "medium", "admin", "Admin path captured"),
]

_COMPILED = [
    (re.compile(pat, re.IGNORECASE), sev, cat, desc)
    for pat, sev, cat, desc in SENSITIVE_URL_PATTERNS
]


class WaybackScanner(BaseScannerModule):
    """Scan Wayback Machine archive for historically exposed sensitive URLs."""

    MAX_CDX_RESULTS = 5000

    @property
    def module_name(self) -> str:
        return "wayback_scanner"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = target.lower().strip().removeprefix("https://").removeprefix("http://").split("/")[0]

        result: Dict[str, Any] = {
            "domain": domain,
            "total_urls_checked": 0,
            "findings": [],
            "interesting_urls": [],
            "wayback_link": f"https://web.archive.org/web/*/{domain}",
            "summary": {
                "score": 100,
                "findings_count": 0,
                "earliest_capture": None,
                "latest_capture": None,
                "total_captures": 0,
            },
        }

        entries = self._query_cdx(domain)
        result["summary"]["total_captures"] = len(entries)

        if not entries:
            logger.info(f"[Wayback] No CDX captures found for {domain}")
            return result

        # Extract timestamps
        timestamps = [e.get("timestamp", "") for e in entries if e.get("timestamp")]
        if timestamps:
            result["summary"]["earliest_capture"] = min(timestamps)[:8]
            result["summary"]["latest_capture"] = max(timestamps)[:8]

        # Scan for sensitive patterns
        seen: Set[str] = set()
        findings: List[Dict] = []
        interesting: List[Dict] = []

        for entry in entries:
            url = entry.get("original", "")
            if not url or url in seen:
                continue
            seen.add(url)

            for regex, sev, cat, desc in _COMPILED:
                if regex.search(url):
                    findings.append({
                        "severity": sev,
                        "title": desc,
                        "detail": url[:200],
                        "url": url,
                        "category": cat,
                        "timestamp": entry.get("timestamp", "")[:8],
                        "wayback_url": f"https://web.archive.org/web/{entry.get('timestamp','*')}/{url}",
                    })
                    break

        # Secret-diff (#72): a sensitive URL still live today is already covered
        # by the active scanners (content_discovery, git_exposure_scanner, etc.)
        # — the genuinely novel signal here is a secret the org believes it
        # removed, but which archive.org still serves. Check liveness only for
        # critical/high findings (bounded set) and flag the removed-but-archived
        # ones as their own, more urgent category.
        for f in findings:
            if f["severity"] not in ("critical", "high"):
                continue
            still_live = self._is_still_live(f["url"])
            f["still_live"] = still_live
            if still_live is False:
                f["category"] = "removed_but_archived"
                f["title"] = f"REMOVED BUT STILL ARCHIVED: {f['title']}"
                f["detail"] = (
                    f"{f['detail']} — no longer reachable on the live site, but still "
                    "retrievable via Wayback Machine. The org likely believes this was deleted."
                )

        result["total_urls_checked"] = len(seen)
        result["findings"] = findings

        # Interesting URLs (API endpoints seen historically)
        for entry in entries[:500]:
            url = entry.get("original", "")
            if any(kw in url.lower() for kw in ["/api/", "swagger", "openapi", "/graphql", "/v1/", "/v2/"]):
                if url not in [x["url"] for x in interesting]:
                    interesting.append({
                        "url": url[:200],
                        "timestamp": entry.get("timestamp", "")[:8],
                    })
        result["interesting_urls"] = interesting[:20]

        score = 100
        for f in findings:
            if f["severity"] == "critical":
                score -= 15
            elif f["severity"] == "high":
                score -= 10
            elif f["severity"] == "medium":
                score -= 5
            elif f["severity"] == "low":
                score -= 2

        result["summary"]["score"] = max(0, score)
        result["summary"]["findings_count"] = len(findings)

        return result

    def _is_still_live(self, url: str) -> Optional[bool]:
        """True if the URL still resolves live, False if it's gone (404/refused),
        None if we couldn't determine (network error — don't claim removed)."""
        try:
            resp = requests.head(url, timeout=8, allow_redirects=True)
            if resp.status_code == 404:
                return False
            if resp.status_code < 400:
                return True
            return None
        except Exception:
            return None

    def _query_cdx(self, domain: str) -> List[Dict]:
        try:
            params = {
                "url": f"*.{domain}/*",
                "output": "json",
                "fl": "original,timestamp,statuscode,mimetype",
                "collapse": "urlkey",
                "limit": self.MAX_CDX_RESULTS,
                "filter": "statuscode:200",
            }
            resp = requests.get(CDX_API, params=params, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            rows = resp.json()
            if not rows or len(rows) < 2:
                return []
            header = rows[0]
            return [dict(zip(header, row)) for row in rows[1:]]
        except Exception as e:
            logger.warning(f"[Wayback] CDX query failed: {e}")
            return []
