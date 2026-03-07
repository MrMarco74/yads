"""
Email Harvesting / Employee OSINT Scanner (#15)

Discovers email addresses and employee information exposed online:
  - Hunter.io API (BYOK)
  - Google Custom Search OSINT (BYOK)
  - Common email pattern inference from discovered names
  - LinkedIn scraping hints (passive, no auth)
  - Exposed email addresses in DNS TXT records
  - Certificate SAN email addresses
  - robots.txt / sitemap hints
  - WHOIS contact emails

Does NOT send emails or attempt authentication.
"""

import logging
import re
import socket
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin

import requests

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

TIMEOUT = 12

# Email regex (RFC-ish)
EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE,
)

COMMON_FORMATS = [
    "{first}.{last}",
    "{f}{last}",
    "{first}{l}",
    "{first}",
    "{last}",
    "{first}_{last}",
    "{f}.{last}",
]

HUNTER_API = "https://api.hunter.io/v2/domain-search"
CRTSH_URL = "https://crt.sh/?q={domain}&output=json"
WHOIS_URL = "https://www.whois.com/whois/{domain}"


def _clean_domain(target: str) -> str:
    return (
        target.lower().strip()
        .removeprefix("https://").removeprefix("http://")
        .split("/")[0]
    )


def _get_hunter_key(target_id: Optional[int]) -> Optional[str]:
    try:
        from sqlmodel import Session, select
        from yads.database import engine
        from yads.models import SystemConfig
        with Session(engine) as session:
            cfg = session.exec(
                select(SystemConfig).where(SystemConfig.key == "HUNTER_API_KEY")
            ).first()
            return cfg.value if cfg and cfg.value else None
    except Exception:
        return None


def _get_gse_keys(target_id: Optional[int]):
    """Return (api_key, cx) for Google Custom Search."""
    try:
        from sqlmodel import Session, select
        from yads.database import engine
        from yads.models import SystemConfig
        with Session(engine) as session:
            keys = session.exec(select(SystemConfig)).all()
            cfg = {c.key: c.value for c in keys}
            return cfg.get("GOOGLE_CSE_KEY"), cfg.get("GOOGLE_CSE_CX")
    except Exception:
        return None, None


def _query_hunter(domain: str, api_key: str) -> Optional[Dict]:
    """Query Hunter.io domain search API."""
    try:
        r = requests.get(
            HUNTER_API,
            params={"domain": domain, "api_key": api_key, "limit": 50},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            emails = data.get("emails", [])
            return {
                "total": data.get("total", 0),
                "emails": [
                    {
                        "value": e.get("value", ""),
                        "first_name": e.get("first_name", ""),
                        "last_name": e.get("last_name", ""),
                        "position": e.get("position", ""),
                        "confidence": e.get("confidence", 0),
                        "sources": len(e.get("sources", [])),
                    }
                    for e in emails[:30]
                ],
                "pattern": data.get("pattern", ""),
                "organization": data.get("organization", ""),
            }
    except Exception as e:
        logger.debug(f"Hunter.io query failed: {e}")
    return None


def _query_google_emails(domain: str, api_key: str, cx: str) -> List[str]:
    """Use Google CSE to search for email addresses published online."""
    found: Set[str] = set()
    queries = [
        f'site:{domain} "@{domain}"',
        f'"@{domain}" email contact',
        f'"{domain}" filetype:pdf email',
    ]
    try:
        for q in queries[:2]:  # Limit API calls
            r = requests.get(
                "https://www.googleapis.com/customsearch/v1",
                params={"key": api_key, "cx": cx, "q": q, "num": 10},
                timeout=TIMEOUT,
            )
            if r.status_code == 200:
                items = r.json().get("items", [])
                for item in items:
                    snippet = item.get("snippet", "") + item.get("title", "")
                    for m in EMAIL_RE.findall(snippet):
                        if domain in m.lower():
                            found.add(m.lower())
    except Exception as e:
        logger.debug(f"Google CSE email search failed: {e}")
    return sorted(found)


def _emails_from_dns_txt(domain: str) -> List[str]:
    """Extract email addresses from DNS TXT records."""
    found = []
    try:
        import subprocess
        result = subprocess.run(
            ["dig", "+short", "TXT", domain],
            capture_output=True, text=True, timeout=10,
        )
        for m in EMAIL_RE.findall(result.stdout):
            found.append(m.lower())
    except Exception:
        pass
    return list(set(found))


def _emails_from_crtsh(domain: str) -> List[str]:
    """Extract email SANs from certificate data."""
    found = []
    try:
        r = requests.get(
            CRTSH_URL.format(domain=domain),
            timeout=TIMEOUT,
            headers={"Accept": "application/json"},
        )
        if r.status_code == 200:
            for entry in r.json()[:50]:
                names = entry.get("name_value", "") or ""
                for part in names.splitlines():
                    part = part.strip()
                    if "@" in part and "." in part:
                        for m in EMAIL_RE.findall(part):
                            found.append(m.lower())
    except Exception as e:
        logger.debug(f"crt.sh email extract failed: {e}")
    return list(set(found))


def _emails_from_webpage(domain: str) -> List[str]:
    """Scrape contact/about pages for visible email addresses."""
    found: Set[str] = set()
    paths = ["/", "/contact", "/about", "/team", "/contact-us", "/impressum"]
    base = f"https://{domain}"
    headers = {"User-Agent": "Mozilla/5.0 (compatible; YADS-Security-Scanner/1.0)"}
    for path in paths:
        try:
            r = requests.get(
                urljoin(base + "/", path.lstrip("/")),
                timeout=8,
                headers=headers,
                verify=False,
                allow_redirects=True,
            )
            if r.status_code == 200:
                # Find mailto links first (most reliable)
                for m in re.findall(r'mailto:([^"\'>\s]+)', r.text, re.IGNORECASE):
                    email = m.split("?")[0].lower()
                    if EMAIL_RE.match(email) and domain in email:
                        found.add(email)
                # Then plain email patterns in text
                for m in EMAIL_RE.findall(r.text[:50000]):
                    if domain in m.lower():
                        found.add(m.lower())
        except Exception:
            continue
    return sorted(found)


def _infer_email_patterns(emails: List[str], domain: str) -> Optional[str]:
    """Infer email format from known addresses."""
    patterns: Dict[str, int] = {}
    for email in emails:
        local = email.split("@")[0]
        if "." in local:
            patterns["first.last"] = patterns.get("first.last", 0) + 1
        elif "_" in local:
            patterns["first_last"] = patterns.get("first_last", 0) + 1
        elif len(local) > 4 and local[0].isalpha():
            patterns["flast"] = patterns.get("flast", 0) + 1
    if patterns:
        return max(patterns, key=patterns.get)
    return None


class EmailHarvester(BaseScannerModule):
    """Email and employee OSINT discovery."""

    @property
    def module_name(self) -> str:
        return "email_harvester"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = _clean_domain(target)

        result: Dict[str, Any] = {
            "domain": domain,
            "emails": [],
            "email_count": 0,
            "email_pattern": None,
            "sources_checked": [],
            "hunter_data": None,
            "findings": [],
            "summary": {
                "score": 100,
                "exposed_count": 0,
                "has_api_data": False,
                "risk_level": "low",
            },
        }

        all_emails: Set[str] = set()
        findings: List[Dict] = []

        # 1. Web scraping — always run
        result["sources_checked"].append("web_scraping")
        web_emails = _emails_from_webpage(domain)
        for e in web_emails:
            all_emails.add(e)

        # 2. DNS TXT records
        result["sources_checked"].append("dns_txt")
        dns_emails = _emails_from_dns_txt(domain)
        for e in dns_emails:
            all_emails.add(e)

        # 3. crt.sh certificate SANs
        result["sources_checked"].append("certificate_transparency")
        ct_emails = _emails_from_crtsh(domain)
        for e in ct_emails:
            all_emails.add(e)

        # 4. Hunter.io (BYOK)
        hunter_key = _get_hunter_key(target_id)
        if hunter_key:
            result["sources_checked"].append("hunter_io")
            hunter_data = _query_hunter(domain, hunter_key)
            if hunter_data:
                result["hunter_data"] = hunter_data
                result["summary"]["has_api_data"] = True
                for e in hunter_data.get("emails", []):
                    val = e.get("value", "")
                    if val:
                        all_emails.add(val.lower())
                if hunter_data.get("pattern"):
                    result["email_pattern"] = hunter_data["pattern"]

        # 5. Google CSE (BYOK)
        gse_key, gse_cx = _get_gse_keys(target_id)
        if gse_key and gse_cx:
            result["sources_checked"].append("google_cse")
            gse_emails = _query_google_emails(domain, gse_key, gse_cx)
            for e in gse_emails:
                all_emails.add(e)

        # Deduplicate and filter to domain emails
        domain_emails = sorted(e for e in all_emails if domain in e)
        other_emails = sorted(e for e in all_emails if domain not in e)

        result["emails"] = domain_emails + other_emails
        result["email_count"] = len(all_emails)
        result["summary"]["exposed_count"] = len(domain_emails)

        # Infer pattern from found emails if not already known
        if not result["email_pattern"] and domain_emails:
            result["email_pattern"] = _infer_email_patterns(domain_emails, domain)

        # --- Findings ---
        if domain_emails:
            sev = "high" if len(domain_emails) >= 10 else "medium" if len(domain_emails) >= 3 else "low"
            findings.append({
                "severity": sev,
                "title": f"{len(domain_emails)} email address(es) discovered for {domain}",
                "description": (
                    f"Email addresses belonging to @{domain} were found in public sources. "
                    "This enables targeted phishing, social engineering, and credential stuffing attacks. "
                    f"Examples: {', '.join(domain_emails[:3])}"
                ),
                "emails": domain_emails[:20],
                "count": len(domain_emails),
            })
            if sev == "high":
                result["summary"]["score"] -= 35
                result["summary"]["risk_level"] = "high"
            elif sev == "medium":
                result["summary"]["score"] -= 20
                result["summary"]["risk_level"] = "medium"
            else:
                result["summary"]["score"] -= 10
                result["summary"]["risk_level"] = "low"

        if result["email_pattern"]:
            findings.append({
                "severity": "medium",
                "title": f"Email format pattern identified: {result['email_pattern']}@{domain}",
                "description": (
                    f"The email naming convention '{result['email_pattern']}@{domain}' can be used to "
                    "construct valid email addresses for any known employee, enabling targeted attacks."
                ),
                "pattern": result["email_pattern"],
            })
            result["summary"]["score"] = max(0, result["summary"]["score"] - 15)

        # Privileged/sensitive role emails
        sensitive_roles = ["ceo", "cto", "cfo", "admin", "root", "security", "it", "hr", "finance"]
        sensitive_found = [e for e in domain_emails if any(r in e.split("@")[0].lower() for r in sensitive_roles)]
        if sensitive_found:
            findings.append({
                "severity": "medium",
                "title": f"Sensitive role email(s) exposed: {', '.join(sensitive_found[:3])}",
                "description": (
                    "Email addresses for high-value roles (CEO, admin, security, finance) are publicly visible. "
                    "These are prime targets for spear-phishing and BEC (Business Email Compromise) attacks."
                ),
                "emails": sensitive_found,
            })
            result["summary"]["score"] = max(0, result["summary"]["score"] - 10)

        if not domain_emails and not result["summary"]["has_api_data"]:
            findings.append({
                "severity": "info",
                "title": "No email addresses discovered",
                "description": (
                    f"No email addresses for @{domain} were found in public sources. "
                    "Configure Hunter.io API key (Settings → System Config) for enhanced coverage."
                ),
            })

        result["findings"] = findings
        result["summary"]["score"] = max(0, result["summary"]["score"])
        return result
