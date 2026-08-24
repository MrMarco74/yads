"""
DNS History / Passive DNS Scanner (#27)

Retrieves historical DNS records to reveal:
- Previously used IP addresses (useful for origin IP discovery behind CDN)
- Historical subdomains (expand attack surface)
- Infrastructure changes over time
- Old IPs that may still host dev/staging versions

Data sources (all free, no API key required):
  1. HackerTarget Passive DNS API
  2. crt.sh (Certificate Transparency — historical subdomains)
  3. SecurityTrails API (if SECURITYTRAILS_API_KEY configured)
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

import requests

from yads.core.api_block_detection import ApiBlockedError
from yads.core.base import BaseScannerModule
from yads.core.throttled_http import throttled_get

logger = logging.getLogger(__name__)

TIMEOUT = 12
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"
HACKERTARGET_PDNS_URL = "https://api.hackertarget.com/reversedns/?q={domain}"
CRTSH_URL = "https://crt.sh/?q={domain}&output=json"
SECURITYTRAILS_URL = "https://api.securitytrails.com/v1/history/{domain}/dns/a"


def _clean_domain(target: str) -> str:
    return (
        target.lower().strip()
        .removeprefix("https://").removeprefix("http://")
        .split("/")[0]
    )


def _hackertarget_hostsearch(domain: str) -> List[Dict]:
    """HackerTarget host search — returns subdomains with IPs."""
    results = []
    try:
        r = throttled_get(
            HACKERTARGET_URL.format(domain=domain),
            service="hackertarget",
            timeout=TIMEOUT,
        )
        if r.status_code == 200 and "error" not in r.text.lower()[:50]:
            for line in r.text.strip().splitlines():
                if "," in line:
                    parts = line.split(",", 1)
                    results.append({
                        "subdomain": parts[0].strip(),
                        "ip": parts[1].strip(),
                        "source": "hackertarget",
                    })
    except ApiBlockedError:
        raise
    except Exception as e:
        logger.debug(f"HackerTarget hostsearch failed: {e}")
    return results


def _crtsh_history(domain: str) -> List[Dict]:
    """crt.sh Certificate Transparency log — historical subdomains."""
    results = []
    seen: Set[str] = set()
    try:
        r = throttled_get(
            CRTSH_URL.format(domain=domain),
            service="crt_sh",
            timeout=TIMEOUT,
            headers={"Accept": "application/json"},
        )
        if r.status_code == 200:
            certs = r.json()
            for cert in certs:
                names_raw = cert.get("name_value", "")
                not_before = cert.get("not_before", "")
                for name in names_raw.split("\n"):
                    name = name.strip().lstrip("*.")
                    if name and name not in seen and domain in name:
                        seen.add(name)
                        results.append({
                            "subdomain": name,
                            "first_seen": not_before,
                            "issuer": cert.get("issuer_name", ""),
                            "source": "crt.sh",
                        })
    except ApiBlockedError:
        raise
    except Exception as e:
        logger.debug(f"crt.sh query failed: {e}")
    return results


def _securitytrails(domain: str, api_key: str) -> List[Dict]:
    """SecurityTrails historical DNS A records (requires API key)."""
    results = []
    try:
        r = throttled_get(
            SECURITYTRAILS_URL.format(domain=domain),
            service="securitytrails",
            headers={"APIKEY": api_key},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            for record in data.get("records", []):
                for val in record.get("values", []):
                    results.append({
                        "ip": val.get("ip", ""),
                        "first_seen": record.get("first_seen", ""),
                        "last_seen": record.get("last_seen", ""),
                        "source": "securitytrails",
                    })
    except ApiBlockedError:
        raise
    except Exception as e:
        logger.debug(f"SecurityTrails query failed: {e}")
    return results


def _get_securitytrails_key(target_id: Optional[int]) -> Optional[str]:
    """Load SecurityTrails API key from SystemConfig if available."""
    try:
        from yads.database import get_session_direct
        from yads.models import SystemConfig
        from sqlmodel import select, Session
        from yads.database import engine
        with Session(engine) as session:
            cfg = session.exec(
                select(SystemConfig).where(SystemConfig.key == "SECURITYTRAILS_API_KEY")
            ).first()
            return cfg.value if cfg and cfg.value else None
    except Exception:
        return None


class DnsHistoryScanner(BaseScannerModule):
    """Passive DNS history and historical subdomain enumeration."""

    @property
    def module_name(self) -> str:
        return "dns_history_scanner"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = _clean_domain(target)

        result: Dict[str, Any] = {
            "domain": domain,
            "historical_hosts": [],
            "historical_certs": [],
            "historical_ips": [],
            "unique_subdomains": [],
            "unique_ips": [],
            "findings": [],
            "sources_used": [],
            "summary": {
                "score": 100,
                "total_subdomains": 0,
                "total_historical_ips": 0,
                "new_subdomains": 0,
            },
        }

        findings: List[Dict] = []
        all_subdomains: Set[str] = set()
        all_ips: Set[str] = set()

        # Source 1: HackerTarget host search
        ht_hosts = _hackertarget_hostsearch(domain)
        if ht_hosts:
            result["sources_used"].append("hackertarget")
            result["historical_hosts"] = ht_hosts
            for h in ht_hosts:
                all_subdomains.add(h["subdomain"])
                if h.get("ip"):
                    all_ips.add(h["ip"])
            
            if target_id:
                from yads.models import OSINTIntelligence
                existing = self.db.query(OSINTIntelligence).filter_by(
                    target_id=target_id, module_name=self.module_name, data_type="historical_dns"
                ).all()
                seen = {f"{r.data_json.get('subdomain')}_{r.data_json.get('ip')}" for r in existing}
                for h in ht_hosts:
                    key = f"{h.get('subdomain')}_{h.get('ip')}"
                    if key not in seen:
                        self.db.add(OSINTIntelligence(
                            target_id=target_id, module_name=self.module_name,
                            data_type="historical_dns", data_json=h, severity="info"
                        ))
                        seen.add(key)

        # Source 2: crt.sh
        crt_records = _crtsh_history(domain)
        if crt_records:
            result["sources_used"].append("crt.sh")
            result["historical_certs"] = crt_records
            for r2 in crt_records:
                all_subdomains.add(r2["subdomain"])

            if target_id:
                from yads.models import OSINTIntelligence
                existing = self.db.query(OSINTIntelligence).filter_by(
                    target_id=target_id, module_name=self.module_name, data_type="certificate_transparency"
                ).all()
                seen = {f"{r.data_json.get('subdomain')}_{r.data_json.get('first_seen')}" for r in existing}
                for r2 in crt_records:
                    key = f"{r2.get('subdomain')}_{r2.get('first_seen')}"
                    if key not in seen:
                        self.db.add(OSINTIntelligence(
                            target_id=target_id, module_name=self.module_name,
                            data_type="certificate_transparency", data_json=r2, severity="info"
                        ))
                        seen.add(key)

        # Source 3: SecurityTrails (if key available)
        st_key = _get_securitytrails_key(target_id)
        if st_key:
            st_records = _securitytrails(domain, st_key)
            if st_records:
                result["sources_used"].append("securitytrails")
                result["historical_ips"] = st_records
                for r3 in st_records:
                    if r3.get("ip"):
                        all_ips.add(r3["ip"])

                if target_id:
                    from yads.models import OSINTIntelligence
                    existing = self.db.query(OSINTIntelligence).filter_by(
                        target_id=target_id, module_name=self.module_name, data_type="historical_ip"
                    ).all()
                    seen = {f"{r.data_json.get('ip')}_{r.data_json.get('first_seen')}" for r in existing}
                    for r3 in st_records:
                        key = f"{r3.get('ip')}_{r3.get('first_seen')}"
                        if key not in seen:
                            self.db.add(OSINTIntelligence(
                                target_id=target_id, module_name=self.module_name,
                                data_type="historical_ip", data_json=r3, severity="info"
                            ))
                            seen.add(key)

        result["unique_subdomains"] = sorted(all_subdomains)
        result["unique_ips"] = sorted(all_ips)
        result["summary"]["total_subdomains"] = len(all_subdomains)
        result["summary"]["total_historical_ips"] = len(all_ips)

        # --- Findings ---
        # 1. Many subdomains discovered = expanded attack surface
        if len(all_subdomains) > 50:
            findings.append({
                "severity": "medium",
                "title": f"Large attack surface: {len(all_subdomains)} historical subdomains",
                "description": (
                    f"Passive DNS and certificate transparency logs reveal {len(all_subdomains)} "
                    "subdomains associated with this domain. Large subdomain inventories increase "
                    "attack surface and may include forgotten/unpatched services."
                ),
                "count": len(all_subdomains),
            })
        elif len(all_subdomains) > 10:
            findings.append({
                "severity": "info",
                "title": f"{len(all_subdomains)} historical subdomains discovered",
                "description": "Passive DNS logs reveal multiple subdomains. Review for stale/forgotten services.",
                "count": len(all_subdomains),
            })

        # 2. Multiple historical IPs — may indicate origin IP exposure
        if len(all_ips) > 3:
            findings.append({
                "severity": "low",
                "title": f"Multiple historical IP addresses ({len(all_ips)})",
                "description": (
                    f"DNS history shows {len(all_ips)} different IP addresses over time: "
                    f"{', '.join(sorted(all_ips)[:5])}{'...' if len(all_ips) > 5 else ''}. "
                    "Old IPs may reveal origin servers behind CDNs or host legacy services."
                ),
                "ips": sorted(all_ips),
            })

        # 3. Dev/staging subdomains
        sensitive_patterns = [
            "dev.", "staging.", "stage.", "test.", "qa.", "uat.", "pre.",
            "preprod.", "demo.", "sandbox.", "internal.", "admin.", "api.",
            "backend.", "old.", "legacy.", "beta.",
        ]
        exposed_sensitive = [
            s for s in all_subdomains
            if any(s.startswith(p) or f".{p.rstrip('.')}" in s for p in sensitive_patterns)
        ]
        if exposed_sensitive:
            findings.append({
                "severity": "low",
                "title": f"Sensitive subdomains in DNS history ({len(exposed_sensitive)})",
                "description": (
                    f"Found {len(exposed_sensitive)} subdomains with sensitive naming patterns "
                    f"(dev/staging/admin/api): {', '.join(sorted(exposed_sensitive)[:8])}"
                ),
                "subdomains": sorted(exposed_sensitive),
            })

        result["findings"] = findings
        result["summary"]["score"] = 100  # Informational scanner — no penalty
        return result
