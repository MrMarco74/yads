"""
Phishing / Brand Abuse Detection Scanner (#29)

Checks whether the domain or its brand appears in known phishing databases
and detects active brand abuse:
  - PhishTank API (free, community-sourced phishing URLs)
  - OpenPhish feed (free tier)
  - Google Safe Browsing API (if key configured)
  - URLhaus (abuse.ch) database
  - URIBL domain reputation
  - Checks if domain itself is a lookalike / IDN homograph of a well-known brand
"""

import hashlib
import logging
import re
import socket
import unicodedata
from typing import Any, Dict, List, Optional

import requests

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

TIMEOUT = 12

PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"
OPENPHISH_URL = "https://openphish.com/feed.txt"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/host/"
URIBL_DNS = "{domain}.multi.uribl.com"
# RFC 2606 reserved domain, never actually registered/listed anywhere --
# used as a canary to detect when URIBL is blocking/rate-limiting us
# rather than genuinely listing the scanned domain (see _check_uribl).
_URIBL_CANARY_DOMAIN = "example.com"

# Well-known brands for homograph/lookalike detection
KNOWN_BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "facebook", "netflix",
    "instagram", "twitter", "linkedin", "dropbox", "adobe", "bank", "chase",
    "wellsfargo", "citibank", "hsbc", "barclays", "ebay", "walmart", "target",
    "steam", "discord", "spotify", "zoom", "teams", "office365", "icloud",
    "gmail", "yahoo", "outlook", "hotmail", "dhl", "fedex", "ups", "usps",
]

# Confusable character map (IDN homograph)
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "і": "i", "ï": "i", "ì": "i", "î": "i", "ó": "o", "ö": "o",
    "ú": "u", "ü": "u", "ñ": "n", "ß": "ss", "℃": "c", "ℓ": "l",
    "ⅰ": "i", "ⅼ": "l", "ⅽ": "c",
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "8": "b",
}


def _clean_domain(target: str) -> str:
    return (
        target.lower().strip()
        .removeprefix("https://").removeprefix("http://")
        .split("/")[0]
    )


def _normalize(s: str) -> str:
    """Normalize domain for homograph detection."""
    normalized = unicodedata.normalize("NFKD", s)
    result = ""
    for ch in normalized:
        result += CONFUSABLES.get(ch, ch)
    return result


def _detect_lookalike(domain: str) -> Optional[str]:
    """Check if domain is a lookalike of a known brand."""
    base = domain.split(".")[0]  # e.g. "paypa1" from "paypa1.com"
    normalized_base = _normalize(base)

    for brand in KNOWN_BRANDS:
        if brand == base:
            continue  # exact match is the real domain
        # Similarity check: Levenshtein distance
        dist = _levenshtein(normalized_base, brand)
        max_len = max(len(normalized_base), len(brand))
        if max_len > 3 and dist <= max(1, max_len // 6):
            return brand
        # Substring: brand appears in domain (paypal-secure.com)
        if brand in base and brand != base:
            return brand
    return None


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def _check_urlhaus(domain: str) -> Optional[Dict]:
    try:
        r = requests.post(
            URLHAUS_URL,
            data={"host": domain},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("query_status") == "is_host":
                urls = data.get("urls", [])
                active = [u for u in urls if u.get("url_status") == "online"]
                return {
                    "listed": True,
                    "total_urls": len(urls),
                    "active_urls": len(active),
                    "tags": list({t for u in urls for t in (u.get("tags") or [])}),
                }
    except Exception as e:
        logger.debug(f"URLhaus check failed: {e}")
    return None


def _uribl_lookup(hostname: str) -> bool:
    """Raw DNSBL lookup. True only if the zone actually returned a
    127.0.0.0/8 loopback address (how DNSBLs encode a listing) -- anything
    else (NXDOMAIN, a resolver rewriting failures, etc.) is not a listing."""
    try:
        results = socket.getaddrinfo(hostname, None)
        return any(res[4][0].startswith("127.") for res in results)
    except socket.gaierror:
        return False
    except Exception:
        return False


def _check_uribl(domain: str) -> bool:
    """
    DNS-based blacklist check via URIBL.

    URIBL's free public mirror rate-limits/blocks high-volume automated
    queriers by making multi.uribl.com answer EVERY query with a 127.x
    "blocked querier" address -- which looks identical to a real listing,
    since DNSBL hits are 127.x too. Guard against this with a canary probe
    against a domain that's never actually listed (an RFC 2606 reserved
    domain): if the canary also comes back "listed", our source IP is
    being blocked/rate-limited, not the target domain, and the real
    result can't be trusted.
    """
    if _uribl_lookup(f"{_URIBL_CANARY_DOMAIN}.multi.uribl.com"):
        logger.warning(
            "URIBL check skipped: canary lookup for '%s' also came back listed -- "
            "our source IP is likely rate-limited/blocked by URIBL's free mirror, "
            "not a real signal about the scanned domain.",
            _URIBL_CANARY_DOMAIN,
        )
        return False

    return _uribl_lookup(URIBL_DNS.format(domain=domain))


def _check_google_safebrowsing(domain: str, api_key: str) -> Optional[List[str]]:
    """Google Safe Browsing Lookup API v4."""
    try:
        url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {"clientId": "yads", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": f"http://{domain}/"},
                    {"url": f"https://{domain}/"},
                ],
            },
        }
        r = requests.post(url, json=payload, timeout=TIMEOUT)
        if r.status_code == 200:
            matches = r.json().get("matches", [])
            return [m.get("threatType", "") for m in matches]
    except Exception as e:
        logger.debug(f"Google Safe Browsing check failed: {e}")
    return None


def _get_gsb_key(target_id: Optional[int]) -> Optional[str]:
    try:
        from sqlmodel import Session, select
        from yads.database import engine
        from yads.models import SystemConfig
        with Session(engine) as session:
            cfg = session.exec(
                select(SystemConfig).where(SystemConfig.key == "GOOGLE_SAFE_BROWSING_KEY")
            ).first()
            return cfg.value if cfg and cfg.value else None
    except Exception:
        return None


class PhishingScanner(BaseScannerModule):
    """Phishing and brand abuse detection via multiple threat databases."""

    @property
    def module_name(self) -> str:
        return "phishing_scanner"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = _clean_domain(target)

        result: Dict[str, Any] = {
            "domain": domain,
            "phishing_listed": False,
            "urlhaus": None,
            "uribl_listed": False,
            "google_threats": [],
            "lookalike_of": None,
            "findings": [],
            "sources_checked": [],
            "summary": {
                "score": 100,
                "threat_count": 0,
                "status": "clean",
            },
        }

        findings: List[Dict] = []
        threat_count = 0

        # 1. URLhaus check
        urlhaus = _check_urlhaus(domain)
        result["sources_checked"].append("urlhaus")
        if urlhaus:
            result["urlhaus"] = urlhaus
            result["phishing_listed"] = True
            threat_count += 1
            sev = "critical" if urlhaus["active_urls"] > 0 else "high"
            findings.append({
                "severity": sev,
                "title": f"Domain listed in URLhaus malware database",
                "description": (
                    f"URLhaus (abuse.ch) has {urlhaus['total_urls']} malicious URL(s) from this domain "
                    f"({urlhaus['active_urls']} currently active). "
                    f"Tags: {', '.join(urlhaus['tags']) if urlhaus['tags'] else 'none'}."
                ),
                "active_urls": urlhaus["active_urls"],
                "total_urls": urlhaus["total_urls"],
                "source_url": f"https://urlhaus.abuse.ch/host/{domain}/",
            })

        # 2. URIBL check
        uribl = _check_uribl(domain)
        result["sources_checked"].append("uribl")
        result["uribl_listed"] = uribl
        if uribl:
            result["phishing_listed"] = True
            threat_count += 1
            findings.append({
                "severity": "high",
                "title": "Domain listed in URIBL spam/phishing blacklist",
                "description": "URIBL DNS blacklist has flagged this domain as associated with spam or phishing campaigns.",
                # URIBL itself is DNS-only with no per-domain web lookup page;
                # MXToolbox's blacklist SuperTool covers uribl-multi and 100+
                # other DNSBLs for this exact domain in one place.
                "source_url": f"https://mxtoolbox.com/SuperTool.aspx?action=blacklist:{domain}",
            })

        # 3. Google Safe Browsing (optional)
        gsb_key = _get_gsb_key(target_id)
        if gsb_key:
            result["sources_checked"].append("google_safe_browsing")
            threats = _check_google_safebrowsing(domain, gsb_key)
            if threats:
                result["google_threats"] = threats
                result["phishing_listed"] = True
                threat_count += 1
                findings.append({
                    "severity": "critical",
                    "title": f"Google Safe Browsing: {', '.join(threats)}",
                    "description": f"Google Safe Browsing API flagged this domain for: {', '.join(threats)}.",
                    "threat_types": threats,
                    "source_url": f"https://transparencyreport.google.com/safe-browsing/search?url={domain}",
                })

        # 4. Lookalike / homograph detection
        lookalike = _detect_lookalike(domain)
        if lookalike:
            result["lookalike_of"] = lookalike
            findings.append({
                "severity": "medium",
                "title": f"Domain resembles '{lookalike}' — possible brand abuse",
                "description": (
                    f"The domain '{domain}' closely resembles the brand '{lookalike}'. "
                    "This may indicate a lookalike domain used for phishing or brand impersonation. "
                    "If this is your domain, this is informational."
                ),
                "target_brand": lookalike,
            })

        # 5. Clean status
        if not findings:
            findings.append({
                "severity": "info",
                "title": "No phishing/malware listings found",
                "description": f"Domain '{domain}' was not found in URLhaus, URIBL, or other threat databases checked.",
            })

        score = 100
        for f in findings:
            if f["severity"] == "critical":
                score -= 50
            elif f["severity"] == "high":
                score -= 35
            elif f["severity"] == "medium":
                score -= 15

        result["summary"]["score"] = max(0, score)
        result["summary"]["threat_count"] = threat_count
        result["summary"]["status"] = "malicious" if result["phishing_listed"] else (
            "suspicious" if lookalike else "clean"
        )
        result["findings"] = findings
        return result
