"""
Threat Intelligence Feed Integration (Task #28)

Enriches targets with data from:
- AbuseIPDB: IP reputation / abuse reports
- OTX AlienVault: Pulses, malware indicators, threat actors
- VirusTotal: URL/domain/IP verdicts, malicious detections

All API keys are optional — scanner degrades gracefully.
"""

import logging
import socket
from typing import Any, Dict, List, Optional

import requests

from yads.core.base import BaseScannerModule
from yads.config import settings

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 15


class ThreatIntelScanner(BaseScannerModule):
    """Query AbuseIPDB, OTX AlienVault, and VirusTotal for threat intel."""

    @property
    def module_name(self) -> str:
        return "threat_intel"

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = target.lower().strip().removeprefix("https://").removeprefix("http://").split("/")[0]

        result: Dict[str, Any] = {
            "domain": domain,
            "ip": None,
            "abuseipdb": None,
            "otx": None,
            "virustotal": None,
            "findings": [],
            "summary": {
                "score": 100,
                "threat_level": "none",
                "sources_checked": [],
            },
        }

        # Resolve IP for IP-based lookups
        ip = self._resolve_ip(domain)
        result["ip"] = ip

        sources = []

        if settings.ABUSEIPDB_API_KEY and ip:
            result["abuseipdb"] = self._query_abuseipdb(ip)
            sources.append("abuseipdb")
        elif not settings.ABUSEIPDB_API_KEY:
            logger.info("[ThreatIntel] No AbuseIPDB key — skipping")

        if settings.OTX_API_KEY:
            result["otx"] = self._query_otx(domain, ip)
            sources.append("otx")
        else:
            logger.info("[ThreatIntel] No OTX key — skipping")

        if settings.VIRUSTOTAL_API_KEY:
            result["virustotal"] = self._query_virustotal(domain)
            sources.append("virustotal")
        else:
            logger.info("[ThreatIntel] No VirusTotal key — skipping")

        result["summary"]["sources_checked"] = sources
        self._build_summary(result)

        return result

    # ------------------------------------------------------------------
    # IP Resolution
    # ------------------------------------------------------------------

    def _resolve_ip(self, domain: str) -> Optional[str]:
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # AbuseIPDB
    # ------------------------------------------------------------------

    def _query_abuseipdb(self, ip: str) -> Dict[str, Any]:
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code == 401:
                return {"error": "Unauthorized", "status": "auth_error"}
            if resp.status_code == 429:
                return {"error": "Rate limited", "status": "rate_limited"}
            resp.raise_for_status()
            d = resp.json().get("data", {})
            return {
                "status": "ok",
                "ip": d.get("ipAddress"),
                "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "num_distinct_users": d.get("numDistinctUsers", 0),
                "last_reported_at": d.get("lastReportedAt"),
                "isp": d.get("isp"),
                "country_code": d.get("countryCode"),
                "usage_type": d.get("usageType"),
                "domain": d.get("domain"),
                "is_whitelisted": d.get("isWhitelisted", False),
                "categories": self._abuseipdb_categories(d.get("reports", [])),
            }
        except requests.RequestException as e:
            logger.error(f"[ThreatIntel] AbuseIPDB request failed: {e}")
            return {"error": str(e), "status": "request_error"}

    def _abuseipdb_categories(self, reports: List[Dict]) -> List[str]:
        """Extract unique category names from recent reports."""
        CAT_MAP = {
            1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
            4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
            7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
            10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
            13: "VPN IP", 14: "Port Scan", 15: "Hacking",
            16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
            19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
            22: "SSH", 23: "IoT Targeted",
        }
        cats = set()
        for r in reports[:20]:
            for cat_id in (r.get("categories") or []):
                cats.add(CAT_MAP.get(cat_id, f"Cat-{cat_id}"))
        return sorted(cats)

    # ------------------------------------------------------------------
    # OTX AlienVault
    # ------------------------------------------------------------------

    def _query_otx(self, domain: str, ip: Optional[str]) -> Dict[str, Any]:
        results = {}
        headers = {"X-OTX-API-KEY": settings.OTX_API_KEY}

        # Domain lookup
        try:
            resp = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code == 401:
                return {"error": "Unauthorized", "status": "auth_error"}
            resp.raise_for_status()
            d = resp.json()
            results["domain"] = {
                "pulse_count": d.get("pulse_info", {}).get("count", 0),
                "pulses": [
                    {
                        "name": p.get("name"),
                        "tags": (p.get("tags") or [])[:5],
                        "malware_families": p.get("malware_families", []),
                        "adversary": p.get("adversary"),
                        "tlp": p.get("tlp"),
                    }
                    for p in (d.get("pulse_info", {}).get("pulses") or [])[:5]
                ],
                "validation": d.get("validation", []),
                "alexa": d.get("alexa"),
                "whois": d.get("whois"),
            }
        except requests.RequestException as e:
            logger.warning(f"[ThreatIntel] OTX domain lookup failed: {e}")
            results["domain"] = {"error": str(e)}

        # IP lookup
        if ip:
            try:
                resp = requests.get(
                    f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                    headers=headers,
                    timeout=REQUEST_TIMEOUT,
                )
                resp.raise_for_status()
                d = resp.json()
                results["ip"] = {
                    "pulse_count": d.get("pulse_info", {}).get("count", 0),
                    "reputation": d.get("reputation", 0),
                    "country_code": d.get("country_code"),
                    "asn": d.get("asn"),
                }
            except requests.RequestException as e:
                logger.warning(f"[ThreatIntel] OTX IP lookup failed: {e}")
                results["ip"] = {"error": str(e)}

        results["status"] = "ok"
        return results

    # ------------------------------------------------------------------
    # VirusTotal
    # ------------------------------------------------------------------

    def _query_virustotal(self, domain: str) -> Dict[str, Any]:
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code == 401:
                return {"error": "Unauthorized", "status": "auth_error"}
            if resp.status_code == 429:
                return {"error": "Rate limited — VirusTotal public API quota exceeded", "status": "rate_limited"}
            if resp.status_code == 404:
                return {"status": "not_found"}
            resp.raise_for_status()
            d = resp.json().get("data", {}).get("attributes", {})

            stats = d.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            total_engines = malicious + suspicious + harmless + stats.get("undetected", 0)

            # Top malicious engine verdicts
            malicious_engines = [
                {"engine": k, "verdict": v.get("result")}
                for k, v in (d.get("last_analysis_results") or {}).items()
                if v.get("category") in ("malicious", "suspicious")
            ][:10]

            return {
                "status": "ok",
                "domain": domain,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "total_engines": total_engines,
                "malicious_engines": malicious_engines,
                "reputation": d.get("reputation", 0),
                "categories": d.get("categories", {}),
                "popularity_ranks": d.get("popularity_ranks", {}),
                "registrar": d.get("registrar"),
                "last_analysis_date": d.get("last_analysis_date"),
                "tags": d.get("tags", []),
            }
        except requests.RequestException as e:
            logger.error(f"[ThreatIntel] VirusTotal request failed: {e}")
            return {"error": str(e), "status": "request_error"}

    # ------------------------------------------------------------------
    # Summary + Findings
    # ------------------------------------------------------------------

    def _build_summary(self, result: Dict[str, Any]) -> None:
        findings: List[Dict] = []
        score = 100

        # --- AbuseIPDB ---
        abuse = result.get("abuseipdb") or {}
        if abuse.get("status") == "ok":
            conf = abuse.get("abuse_confidence_score", 0)
            reports = abuse.get("total_reports", 0)
            if conf >= 75:
                findings.append({
                    "severity": "critical",
                    "title": f"IP flagged as malicious by AbuseIPDB (confidence: {conf}%)",
                    "detail": f"{reports} abuse reports from {abuse.get('num_distinct_users',0)} users.",
                    "source": "abuseipdb",
                })
                score -= 30
            elif conf >= 25:
                findings.append({
                    "severity": "high",
                    "title": f"IP has abuse reports on AbuseIPDB (confidence: {conf}%)",
                    "detail": f"{reports} reports. Categories: {', '.join(abuse.get('categories',[])[:5])}",
                    "source": "abuseipdb",
                })
                score -= 15
            elif reports > 0:
                findings.append({
                    "severity": "medium",
                    "title": f"IP has {reports} abuse reports on AbuseIPDB",
                    "detail": f"Confidence score: {conf}%",
                    "source": "abuseipdb",
                })
                score -= 5

        # --- OTX ---
        otx = result.get("otx") or {}
        domain_data = otx.get("domain") or {}
        pulse_count = domain_data.get("pulse_count", 0)
        if pulse_count > 0:
            sev = "critical" if pulse_count >= 10 else "high" if pulse_count >= 3 else "medium"
            findings.append({
                "severity": sev,
                "title": f"Domain found in {pulse_count} OTX AlienVault pulse(s)",
                "detail": f"Threat intelligence pulses indicate this domain is associated with malicious activity.",
                "source": "otx",
            })
            score -= min(25, pulse_count * 3)

            # Specific malware families from pulses
            families = set()
            for p in domain_data.get("pulses", []):
                for mf in (p.get("malware_families") or []):
                    if isinstance(mf, dict):
                        families.add(mf.get("display_name", ""))
                    elif isinstance(mf, str):
                        families.add(mf)
            if families:
                findings.append({
                    "severity": "critical",
                    "title": f"Malware families associated: {', '.join(list(families)[:5])}",
                    "detail": "This domain appears in OTX pulses linked to known malware.",
                    "source": "otx",
                })

        # --- VirusTotal ---
        vt = result.get("virustotal") or {}
        if vt.get("status") == "ok":
            malicious = vt.get("malicious", 0)
            suspicious = vt.get("suspicious", 0)
            total = vt.get("total_engines", 1) or 1
            if malicious >= 5:
                findings.append({
                    "severity": "critical",
                    "title": f"VirusTotal: {malicious}/{total} engines flagged as malicious",
                    "detail": f"Engines: {', '.join(e['engine'] for e in vt.get('malicious_engines',[])[:5])}",
                    "source": "virustotal",
                })
                score -= 30
            elif malicious >= 2 or suspicious >= 3:
                findings.append({
                    "severity": "high",
                    "title": f"VirusTotal: {malicious} malicious, {suspicious} suspicious detections",
                    "detail": f"Out of {total} engines.",
                    "source": "virustotal",
                })
                score -= 15
            elif malicious == 1 or suspicious > 0:
                findings.append({
                    "severity": "medium",
                    "title": f"VirusTotal: {malicious + suspicious} detection(s) (low confidence)",
                    "detail": f"One or more engines flagged the domain. May be false positive.",
                    "source": "virustotal",
                })
                score -= 5

            vt_rep = vt.get("reputation", 0)
            if vt_rep < -10:
                findings.append({
                    "severity": "high",
                    "title": f"VirusTotal reputation score: {vt_rep}",
                    "detail": "Negative reputation indicates malicious community votes.",
                    "source": "virustotal",
                })

        # Determine threat level
        has_critical = any(f["severity"] == "critical" for f in findings)
        has_high = any(f["severity"] == "high" for f in findings)
        has_medium = any(f["severity"] == "medium" for f in findings)

        if has_critical:
            threat_level = "critical"
        elif has_high:
            threat_level = "high"
        elif has_medium:
            threat_level = "medium"
        elif findings:
            threat_level = "low"
        else:
            threat_level = "none"

        result["findings"] = findings
        result["summary"]["score"] = max(0, min(100, score))
        result["summary"]["threat_level"] = threat_level
        result["summary"]["findings_count"] = len(findings)
