"""
Certificate Transparency Monitoring (#10)

Monitors Certificate Transparency logs for newly issued certificates:
  - crt.sh real-time CT log search
  - Detects unexpected/unauthorized certificate issuance
  - Wildcard certificate tracking
  - Identifies certificates from unexpected CAs
  - Flags suspicious subdomains in recent certs (lookalike, staging leaked)
  - Precertificate vs. final certificate detection

No external tools required — uses crt.sh JSON API.
"""

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

import requests

from yads.core.api_block_detection import ApiBlockedError
from yads.core.base import BaseScannerModule
from yads.core.throttled_http import throttled_get

logger = logging.getLogger(__name__)

TIMEOUT = 15
CRTSH_URL = "https://crt.sh/?q={domain}&output=json&exclude=expired"
CRTSH_ALL_URL = "https://crt.sh/?q=%.{domain}&output=json"

# Well-known/expected CAs — certs from others may warrant review
TRUSTED_CAS = frozenset([
    "Let's Encrypt", "DigiCert", "Sectigo", "GlobalSign", "Entrust",
    "GoDaddy", "Comodo", "Thawte", "GeoTrust", "RapidSSL", "Amazon",
    "Microsoft", "Google Trust Services", "ZeroSSL", "Buypass",
])

# Suspicious patterns in cert CNs
SUSPICIOUS_PATTERNS = re.compile(
    r"(test|dev|staging|preprod|internal|localhost|admin|secret|vpn|"
    r"backup|old|temp|debug|scan|hack|phish|malware|exploit)",
    re.IGNORECASE,
)


def _clean_domain(target: str) -> str:
    return (
        target.lower().strip()
        .removeprefix("https://").removeprefix("http://")
        .split("/")[0]
    )


def _fetch_certs(domain: str) -> List[Dict]:
    """Fetch all certificates for domain and subdomains from crt.sh."""
    try:
        r = throttled_get(
            CRTSH_ALL_URL.format(domain=domain),
            service="crt_sh",
            timeout=TIMEOUT,
            headers={"Accept": "application/json"},
        )
        if r.status_code == 200:
            return r.json()
    except ApiBlockedError:
        raise
    except Exception as e:
        logger.debug(f"crt.sh fetch failed: {e}")
    return []


def _parse_cert(entry: Dict) -> Optional[Dict]:
    """Normalize a crt.sh entry."""
    try:
        not_before_str = entry.get("not_before", "")
        not_after_str = entry.get("not_after", "")
        try:
            not_before = datetime.fromisoformat(not_before_str.replace("Z", "+00:00"))
            not_after = datetime.fromisoformat(not_after_str.replace("Z", "+00:00"))
        except Exception:
            not_before = None
            not_after = None

        issuer = entry.get("issuer_name", "") or ""
        names_raw = entry.get("name_value", "") or ""
        names = [n.strip() for n in names_raw.splitlines() if n.strip()]

        return {
            "id": entry.get("id"),
            "logged_at": entry.get("entry_timestamp", ""),
            "not_before": not_before_str,
            "not_after": not_after_str,
            "not_before_dt": not_before,
            "not_after_dt": not_after,
            "issuer": issuer,
            "common_name": entry.get("common_name", ""),
            "names": names,
            "is_wildcard": any("*." in n for n in names),
            "is_precert": "Precertificate" in (entry.get("issuer_ca_id", "") or ""),
        }
    except Exception:
        return None


def _extract_ca_name(issuer_str: str) -> str:
    """Extract human-readable CA name from issuer DN."""
    for part in issuer_str.split(","):
        part = part.strip()
        if part.startswith("O="):
            return part[2:].strip().strip('"')
    return issuer_str[:60]


def _is_recent(not_before_dt: Optional[datetime], days: int = 30) -> bool:
    if not_before_dt is None:
        return False
    try:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=days)
        if not_before_dt.tzinfo is None:
            not_before_dt = not_before_dt.replace(tzinfo=timezone.utc)
        return not_before_dt >= cutoff
    except Exception:
        return False


class CtMonitor(BaseScannerModule):
    """Certificate Transparency log monitoring."""

    @property
    def module_name(self) -> str:
        return "ct_monitor"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = _clean_domain(target)

        result: Dict[str, Any] = {
            "domain": domain,
            "total_certs": 0,
            "recent_certs": [],
            "wildcard_certs": [],
            "unique_cas": [],
            "unknown_cas": [],
            "suspicious_names": [],
            "unique_subdomains": [],
            "findings": [],
            "summary": {
                "score": 100,
                "cert_count": 0,
                "recent_count": 0,
                "wildcard_count": 0,
                "unknown_ca_count": 0,
            },
        }

        raw = _fetch_certs(domain)
        if not raw:
            result["error"] = "No CT log data returned from crt.sh"
            return result

        certs = [_parse_cert(e) for e in raw]
        certs = [c for c in certs if c]

        result["total_certs"] = len(certs)
        result["summary"]["cert_count"] = len(certs)

        # Deduplicate by cert ID
        seen_ids: Set[int] = set()
        unique_certs = []
        for c in certs:
            cid = c.get("id")
            if cid not in seen_ids:
                seen_ids.add(cid)
                unique_certs.append(c)

        # Collect subdomains
        all_names: Set[str] = set()
        for c in unique_certs:
            for n in c["names"]:
                if domain in n:
                    all_names.add(n.lstrip("*."))
        result["unique_subdomains"] = sorted(all_names)

        # Recent certs (last 30 days)
        recent = [c for c in unique_certs if _is_recent(c["not_before_dt"], 30)]
        result["recent_certs"] = [
            {
                "id": c["id"],
                "common_name": c["common_name"],
                "issuer": c["issuer"][:80],
                "not_before": c["not_before"],
                "not_after": c["not_after"],
                "names": c["names"][:10],
                "is_wildcard": c["is_wildcard"],
            }
            for c in recent[:20]
        ]
        result["summary"]["recent_count"] = len(recent)

        # Wildcard certs
        wildcards = [c for c in unique_certs if c["is_wildcard"]]
        result["wildcard_certs"] = [
            {"common_name": c["common_name"], "not_before": c["not_before"]}
            for c in wildcards[:10]
        ]
        result["summary"]["wildcard_count"] = len(wildcards)

        # CA analysis
        ca_names: Set[str] = set()
        unknown_cas: Set[str] = set()
        for c in unique_certs:
            ca = _extract_ca_name(c["issuer"])
            ca_names.add(ca)
            # Check if CA is unknown/unexpected
            if not any(t.lower() in ca.lower() for t in TRUSTED_CAS):
                unknown_cas.add(ca)
        result["unique_cas"] = sorted(ca_names)
        result["unknown_cas"] = sorted(unknown_cas)
        result["summary"]["unknown_ca_count"] = len(unknown_cas)

        # Suspicious name patterns in recent certs
        suspicious: List[Dict] = []
        for c in recent:
            for name in c["names"]:
                if SUSPICIOUS_PATTERNS.search(name):
                    suspicious.append({"name": name, "cert_id": c["id"], "not_before": c["not_before"]})
        # Deduplicate by name
        seen_suspicious: Set[str] = set()
        deduped_suspicious = []
        for s in suspicious:
            if s["name"] not in seen_suspicious:
                seen_suspicious.add(s["name"])
                deduped_suspicious.append(s)
        result["suspicious_names"] = deduped_suspicious[:20]

        findings = []
        score = 100

        # --- Findings ---
        if recent:
            findings.append({
                "severity": "info",
                "title": f"{len(recent)} certificate(s) issued in the last 30 days",
                "description": f"Certificate Transparency logs show {len(recent)} recently issued cert(s) for {domain} and its subdomains.",
                "count": len(recent),
            })

        if wildcards:
            sev = "medium" if len(wildcards) > 3 else "low"
            findings.append({
                "severity": sev,
                "title": f"{len(wildcards)} wildcard certificate(s) found",
                "description": (
                    "Wildcard certificates (*.domain) cover all subdomains and reduce "
                    "the benefit of CT monitoring. If compromised, all subdomains are affected."
                ),
                "count": len(wildcards),
            })
            if sev == "medium":
                score -= 10

        if unknown_cas:
            findings.append({
                "severity": "medium",
                "title": f"Certificates from unexpected CA(s): {', '.join(list(unknown_cas)[:3])}",
                "description": (
                    "Certificates were issued by Certificate Authorities not in the common trusted list. "
                    "Verify these are authorized — unexpected CAs may indicate certificate misissuance."
                ),
                "cas": sorted(unknown_cas),
            })
            score -= 15

        if deduped_suspicious:
            names_str = ", ".join(s["name"] for s in deduped_suspicious[:5])
            findings.append({
                "severity": "medium",
                "title": f"Suspicious/internal subdomains in CT logs: {names_str}",
                "description": (
                    "CT logs reveal subdomains with patterns suggesting internal systems (dev, staging, vpn, admin). "
                    "These should not be publicly visible and may expose internal infrastructure."
                ),
                "names": [s["name"] for s in deduped_suspicious],
            })
            score -= 15

        if len(all_names) > 100:
            findings.append({
                "severity": "low",
                "title": f"Large subdomain footprint: {len(all_names)} unique subdomains in CT logs",
                "description": "A large number of subdomains increases attack surface. Consider auditing active vs. abandoned subdomains.",
                "count": len(all_names),
            })
            score -= 5

        if not findings:
            findings.append({
                "severity": "info",
                "title": "Certificate Transparency logs checked",
                "description": f"No concerning CT log entries found for {domain}.",
            })

        result["findings"] = findings
        result["summary"]["score"] = max(0, score)
        return result
