"""
Shodan / Censys Integration Scanner (Task #6)

Enriches targets with data from Shodan and/or Censys:
- Open ports and services
- Software versions and CVEs
- OS detection
- Vulnerability findings (Shodan vulns feed)
- IP reputation / country / ASN info

API keys are optional — the scanner degrades gracefully when keys are absent.
"""

import logging
import socket
from typing import Any, Dict, List, Optional

import requests

from yads.core.base import BaseScannerModule, ApiKeySpec
from yads.core.api_rate_limiter import get_api_rate_limiter
from yads.core.tenant_keys import get_tenant_api_key
from yads.config import settings

logger = logging.getLogger(__name__)


# Severity mapping for Shodan vuln CVSSv2 scores
def _cvss_to_severity(cvss: Optional[float]) -> str:
    if cvss is None:
        return "medium"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


class ShodanCensysScanner(BaseScannerModule):
    """Query Shodan and/or Censys for host intelligence on a target domain."""

    SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
    SHODAN_DNS_URL  = "https://api.shodan.io/dns/resolve"
    CENSYS_HOST_URL = "https://search.censys.io/api/v2/hosts/{ip}"

    REQUEST_TIMEOUT = 15

    api_key_specs = [
        ApiKeySpec(
            name="shodan_api_key",
            label="Shodan API Key",
            description="Port scanning, banner grabbing and CVE lookup via Shodan.",
            placeholder="wQcGl4ih...",
            help_url="https://account.shodan.io/",
            settings_fallback="SHODAN_API_KEY",
        ),
        ApiKeySpec(
            name="censys_api_key",
            label="Censys API Key",
            description="Host and certificate intelligence from Censys.",
            placeholder="censys_dT1aJPod...",
            help_url="https://search.censys.io/account/api",
            settings_fallback="CENSYS_API_ID",
        ),
    ]

    @property
    def module_name(self) -> str:
        return "shodan_censys"

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run_scan(self, target: str, target_id: Optional[int] = None, tenant_id: Optional[int] = None) -> Dict[str, Any]:
        domain = target.lower().strip().removeprefix("https://").removeprefix("http://").split("/")[0]

        shodan_key = get_tenant_api_key(self.db, tenant_id, "shodan_api_key", settings_fallback="SHODAN_API_KEY")
        censys_key = get_tenant_api_key(self.db, tenant_id, "censys_api_key", settings_fallback="CENSYS_API_ID")

        result: Dict[str, Any] = {
            "domain": domain,
            "ip": None,
            "shodan": None,
            "censys": None,
            "findings": [],
            "summary": {
                "open_ports": [],
                "cves": [],
                "os": None,
                "country": None,
                "asn": None,
                "org": None,
                "score": 100,
            },
        }

        # 1. Resolve IP
        ip = self._resolve_ip(domain)
        if not ip:
            logger.warning(f"[ShodanCensys] Could not resolve {domain}")
            result["error"] = f"Could not resolve IP for {domain}"
            return result

        result["ip"] = ip
        logger.info(f"[ShodanCensys] Resolved {domain} → {ip}")

        # 2. Shodan enrichment
        if shodan_key:
            result["shodan"] = self._query_shodan(ip, domain, shodan_key)
        else:
            logger.info("[ShodanCensys] No Shodan API key — skipping Shodan lookup")

        # 3. Censys enrichment
        if censys_key:
            result["censys"] = self._query_censys(ip, censys_key)
        else:
            logger.info("[ShodanCensys] No Censys API key — skipping Censys lookup")

        # 4. Merge into unified summary + findings
        self._build_summary(result, target_id)

        return result

    # ------------------------------------------------------------------
    # IP resolution
    # ------------------------------------------------------------------

    def _resolve_ip(self, domain: str) -> Optional[str]:
        try:
            return socket.gethostbyname(domain)
        except Exception as e:
            logger.debug(f"[ShodanCensys] DNS resolve error for {domain}: {e}")
            return None

    # ------------------------------------------------------------------
    # Shodan
    # ------------------------------------------------------------------

    def _query_shodan(self, ip: str, domain: str, api_key: str) -> Dict[str, Any]:
        """Fetch host data from Shodan API."""
        limiter = get_api_rate_limiter()
        if not limiter.acquire("shodan", timeout=10.0):
            logger.warning("[ShodanCensys] Shodan rate limit exceeded, skipping")
            return {"error": "Rate limit exceeded", "status": "rate_limited"}
        try:
            resp = requests.get(
                self.SHODAN_HOST_URL.format(ip=ip),
                params={"key": api_key},
                timeout=self.REQUEST_TIMEOUT,
            )
            if resp.status_code == 404:
                logger.info(f"[ShodanCensys] Shodan: no data for {ip}")
                return {"status": "not_found"}
            if resp.status_code == 401:
                logger.warning("[ShodanCensys] Shodan API key invalid or quota exceeded")
                return {"error": "Unauthorized", "status": "auth_error"}
            resp.raise_for_status()
            data = resp.json()
            return self._parse_shodan(data)
        except requests.RequestException as e:
            logger.error(f"[ShodanCensys] Shodan request failed: {e}")
            return {"error": str(e), "status": "request_error"}

    def _parse_shodan(self, raw: Dict) -> Dict[str, Any]:
        ports = sorted(set(raw.get("ports", [])))

        services = []
        for item in raw.get("data", []):
            svc = {
                "port": item.get("port"),
                "proto": item.get("transport", "tcp"),
                "product": item.get("product"),
                "version": item.get("version"),
                "cpe": item.get("cpe", []),
                "banner": (item.get("data") or "")[:300],
            }
            services.append(svc)

        # CVEs from Shodan vulns field
        cves = []
        for cve_id, vuln in (raw.get("vulns") or {}).items():
            cves.append({
                "cve": cve_id,
                "cvss": vuln.get("cvss"),
                "summary": vuln.get("summary", ""),
                "severity": _cvss_to_severity(vuln.get("cvss")),
                "references": (vuln.get("references") or [])[:3],
            })

        # Sort by CVSS descending
        cves.sort(key=lambda x: (x.get("cvss") or 0), reverse=True)

        return {
            "status": "ok",
            "ip": raw.get("ip_str"),
            "hostnames": raw.get("hostnames", []),
            "domains": raw.get("domains", []),
            "country": raw.get("country_code"),
            "country_name": raw.get("country_name"),
            "city": raw.get("city"),
            "org": raw.get("org"),
            "asn": raw.get("asn"),
            "isp": raw.get("isp"),
            "os": raw.get("os"),
            "last_update": raw.get("last_update"),
            "ports": ports,
            "services": services,
            "cves": cves,
            "tags": raw.get("tags", []),
        }

    # ------------------------------------------------------------------
    # Censys
    # ------------------------------------------------------------------

    def _query_censys(self, ip: str, api_key: str) -> Dict[str, Any]:
        """Fetch host data from Censys v2 API. api_key may be 'id:secret' or just the key."""
        limiter = get_api_rate_limiter()
        if not limiter.acquire("censys", timeout=10.0):
            logger.warning("[ShodanCensys] Censys rate limit exceeded, skipping")
            return {"error": "Rate limit exceeded", "status": "rate_limited"}
        # Support "id:secret" format or legacy separate CENSYS_API_SECRET env var
        if ":" in api_key:
            censys_id, censys_secret = api_key.split(":", 1)
        else:
            censys_id = api_key
            censys_secret = settings.CENSYS_API_SECRET or ""
        try:
            resp = requests.get(
                self.CENSYS_HOST_URL.format(ip=ip),
                auth=(censys_id, censys_secret),
                timeout=self.REQUEST_TIMEOUT,
            )
            if resp.status_code == 404:
                logger.info(f"[ShodanCensys] Censys: no data for {ip}")
                return {"status": "not_found"}
            if resp.status_code in (401, 403):
                logger.warning("[ShodanCensys] Censys API credentials invalid")
                return {"error": "Unauthorized", "status": "auth_error"}
            resp.raise_for_status()
            data = resp.json().get("result", {})
            return self._parse_censys(data)
        except requests.RequestException as e:
            logger.error(f"[ShodanCensys] Censys request failed: {e}")
            return {"error": str(e), "status": "request_error"}

    def _parse_censys(self, data: Dict) -> Dict[str, Any]:
        services = []
        for svc in data.get("services", []):
            services.append({
                "port": svc.get("port"),
                "proto": svc.get("transport_protocol", "TCP").lower(),
                "service_name": svc.get("service_name"),
                "product": (svc.get("software") or [{}])[0].get("product") if svc.get("software") else None,
                "version": (svc.get("software") or [{}])[0].get("version") if svc.get("software") else None,
                "tls": svc.get("tls") is not None,
                "observed_at": svc.get("observed_at"),
            })

        ports = sorted(set(s["port"] for s in services if s["port"]))

        location = data.get("location", {})
        autonomous_system = data.get("autonomous_system", {})

        return {
            "status": "ok",
            "ip": data.get("ip"),
            "country": location.get("country_code"),
            "country_name": location.get("country"),
            "city": location.get("city"),
            "asn": f"AS{autonomous_system.get('asn')}" if autonomous_system.get("asn") else None,
            "org": autonomous_system.get("name"),
            "bgp_prefix": autonomous_system.get("bgp_prefix"),
            "ports": ports,
            "services": services,
            "last_updated": data.get("last_updated_at"),
            "labels": data.get("labels", []),
        }

    # ------------------------------------------------------------------
    # Summary + Findings
    # ------------------------------------------------------------------

    def _build_summary(self, result: Dict[str, Any], target_id: Optional[int] = None) -> None:
        shodan = result.get("shodan") or {}
        censys = result.get("censys") or {}
        findings: List[Dict] = []
        score = 100
        
        from yads.models import OSINTIntelligence
        import datetime

        # Merge ports (prefer Shodan, fill with Censys)
        ports = set()
        if shodan.get("ports"):
            ports.update(shodan["ports"])
        if censys.get("ports"):
            ports.update(censys["ports"])
        result["summary"]["open_ports"] = sorted(ports)

        # OS
        result["summary"]["os"] = shodan.get("os") or None

        # Country / ASN / Org — prefer Shodan
        result["summary"]["country"] = shodan.get("country") or censys.get("country")
        result["summary"]["asn"] = shodan.get("asn") or censys.get("asn")
        result["summary"]["org"] = shodan.get("org") or censys.get("org")

        # CVEs (Shodan only for now)
        cves = shodan.get("cves", [])
        result["summary"]["cves"] = [c["cve"] for c in cves]

        # --- Generate findings ---

        # CVE findings
        for cve in cves:
            if target_id and self.db:
                existing = self.db.query(OSINTIntelligence).filter_by(
                    target_id=target_id, module_name=self.module_name, data_type="vulnerability"
                ).filter(OSINTIntelligence.data_json["cve"].astext == cve["cve"]).first()
                if not existing:
                    self.db.add(OSINTIntelligence(
                        target_id=target_id, module_name=self.module_name, data_type="vulnerability",
                        data_json={"cve": cve["cve"], "summary": cve.get("summary", ""), "severity": cve["severity"]},
                        severity=cve["severity"], timestamp=datetime.datetime.utcnow()
                    ))

            findings.append({
                "type": "cve",
                "title": f"Known vulnerability: {cve['cve']}",
                "detail": cve.get("summary", "")[:200],
                "severity": cve["severity"],
                "source": "shodan",
                "reference": cve["cve"],
            })
            if cve["severity"] in ("critical", "high"):
                score -= 15
            elif cve["severity"] == "medium":
                score -= 8
            else:
                score -= 3

        # Unusual / risky open ports
        RISKY_PORTS = {
            21: ("FTP open", "medium"),
            23: ("Telnet open", "high"),
            25: ("SMTP open to internet", "medium"),
            445: ("SMB/CIFS open", "high"),
            3389: ("RDP open to internet", "high"),
            5900: ("VNC open", "high"),
            6379: ("Redis open (unauthenticated?)", "critical"),
            27017: ("MongoDB open (unauthenticated?)", "critical"),
            9200: ("Elasticsearch open", "critical"),
            11211: ("Memcached open", "high"),
            2181: ("ZooKeeper open", "high"),
            5432: ("PostgreSQL open to internet", "high"),
            3306: ("MySQL open to internet", "high"),
            1433: ("MSSQL open to internet", "high"),
        }
        for port in sorted(ports):
            if target_id and self.db:
                existing = self.db.query(OSINTIntelligence).filter_by(
                    target_id=target_id, module_name=self.module_name, data_type="open_port"
                ).filter(OSINTIntelligence.data_json["port"].astext == str(port)).first()
                if not existing:
                    self.db.add(OSINTIntelligence(
                        target_id=target_id, module_name=self.module_name, data_type="open_port",
                        data_json={"port": port},
                        severity="info", timestamp=datetime.datetime.utcnow()
                    ))

            if port in RISKY_PORTS:
                msg, sev = RISKY_PORTS[port]
                findings.append({
                    "type": "open_port",
                    "title": f"Port {port}: {msg}",
                    "detail": f"Port {port} is exposed to the internet. Verify this is intentional.",
                    "severity": sev,
                    "source": "shodan_censys",
                    "reference": str(port),
                })
                if sev == "critical":
                    score -= 20
                elif sev == "high":
                    score -= 10
                elif sev == "medium":
                    score -= 5

        # Shodan tags
        RISKY_TAGS = {
            "honeypot": ("Host flagged as honeypot", "info"),
            "malware": ("Host associated with malware", "critical"),
            "self-signed": ("Self-signed TLS certificate", "medium"),
            "c2": ("Host flagged as C2 server", "critical"),
            "tor": ("Host is a Tor exit node", "high"),
        }
        for tag in shodan.get("tags", []):
            if target_id and self.db:
                existing = self.db.query(OSINTIntelligence).filter_by(
                    target_id=target_id, module_name=self.module_name, data_type="shodan_tag"
                ).filter(OSINTIntelligence.data_json["tag"].astext == tag).first()
                if not existing:
                    self.db.add(OSINTIntelligence(
                        target_id=target_id, module_name=self.module_name, data_type="shodan_tag",
                        data_json={"tag": tag},
                        severity="info", timestamp=datetime.datetime.utcnow()
                    ))

            if tag in RISKY_TAGS:
                msg, sev = RISKY_TAGS[tag]
                findings.append({
                    "type": "shodan_tag",
                    "title": f"Shodan flag: {tag} — {msg}",
                    "detail": f"Shodan has tagged this host as '{tag}'.",
                    "severity": sev,
                    "source": "shodan",
                    "reference": tag,
                })

        score = max(0, min(100, score))
        result["summary"]["score"] = score
        result["findings"] = findings
        result["summary"]["findings_count"] = len(findings)
        
        if target_id and self.db:
            try:
                self.db.commit()
            except Exception as e:
                logger.error(f"[ShodanCensys] DB Commit failed: {e}")
                self.db.rollback()
