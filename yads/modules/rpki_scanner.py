"""
RPKI / BGP Route Validation Scanner

Checks whether IP addresses of a target have valid RPKI Route Origin
Authorizations (ROAs). RPKI-invalid or unprotected prefixes are vulnerable
to BGP hijacking — an attacker can announce the same prefix from a different
AS and intercept traffic.

Uses RIPE Stat API (free, no API key required):
- network-info: resolves IP → ASN + prefix
- rpki-validation: checks ROA validity for ASN+prefix pair
- Also fetches basic ASN/org info via ipinfo.io as fallback
"""

import logging
import socket
from typing import Any, Dict, List, Optional

from yads.core.base import BaseScannerModule
from yads.core.throttled_http import throttled_get

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 12
RIPE_STAT = "https://stat.ripe.net/data"


class RpkiScanner(BaseScannerModule):
    """ASN discovery + RPKI route origin validation."""

    @property
    def module_name(self) -> str:
        return "rpki_scanner"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = (
            target.lower().strip()
            .removeprefix("https://").removeprefix("http://")
            .split("/")[0]
        )

        result: Dict[str, Any] = {
            "domain": domain,
            "ips": [],
            "routes": [],
            "findings": [],
            "summary": {
                "score": 100,
                "valid": 0,
                "invalid": 0,
                "not_found": 0,
                "asns": [],
                "orgs": [],
            },
        }

        ips = self._resolve_ips(domain)
        if not ips:
            result["error"] = "Domain did not resolve"
            return result

        result["ips"] = ips
        seen_prefixes: set = set()

        for ip in ips:
            net = self._get_network_info(ip)
            if not net:
                continue

            asn = net.get("asn", "")
            prefix = net.get("prefix", "")

            if not asn or not prefix or prefix in seen_prefixes:
                continue
            seen_prefixes.add(prefix)

            rpki = self._check_rpki(asn, prefix)
            state = rpki.get("state", "unknown")

            org = net.get("org", "")
            route_entry = {
                "ip": ip,
                "asn": asn,
                "prefix": prefix,
                "org": org,
                "country": net.get("country", ""),
                "rpki_state": state,
                "roas": rpki.get("roas", []),
            }
            result["routes"].append(route_entry)

            if asn not in result["summary"]["asns"]:
                result["summary"]["asns"].append(asn)
            if org and org not in result["summary"]["orgs"]:
                result["summary"]["orgs"].append(org)

            if state == "valid":
                result["summary"]["valid"] += 1
            elif state == "invalid":
                result["summary"]["invalid"] += 1
                result["findings"].append({
                    "severity": "high",
                    "title": f"RPKI Invalid: {prefix} via AS{asn}",
                    "detail": (
                        f"Prefix {prefix} is announced by AS{asn} ({org}) but the "
                        f"Route Origin Authorization says this is NOT permitted. "
                        f"This is a strong indicator of BGP route hijacking."
                    ),
                    "category": "rpki_invalid",
                    "asn": asn,
                    "prefix": prefix,
                })
            else:
                result["summary"]["not_found"] += 1
                result["findings"].append({
                    "severity": "medium",
                    "title": f"No RPKI ROA: {prefix} (AS{asn})",
                    "detail": (
                        f"No Route Origin Authorization found for {prefix}. "
                        f"The prefix is unprotected — any AS could announce it "
                        f"and intercept traffic without RPKI filtering catching it."
                    ),
                    "category": "rpki_not_found",
                    "asn": asn,
                    "prefix": prefix,
                })

        # Continuous route-origin monitoring (#36): a BGP hijack shows up as
        # the announcing ASN for one of the target's IPs suddenly changing
        # between scans — a much more time-critical signal than the static
        # RPKI-valid/invalid check above, which only catches hijacks that
        # violate an existing ROA (no ROA = no protection either way). Diff
        # each IP's ASN against the last-seen value via baseline_diff.
        if target_id:
            try:
                from yads.database import engine as _engine
                from sqlmodel import Session as _Session
                from yads.core.baseline_diff import diff_against_last
                for route in result["routes"]:
                    ip, asn = route["ip"], route["asn"]
                    with _Session(_engine) as _db:
                        diff = diff_against_last(_db, f"rpki_origin_asn:{ip}", [asn], target_id=target_id)
                    if not diff["is_first"] and diff["removed"]:
                        old_asn = diff["removed"][0]
                        result["findings"].append({
                            "severity": "critical",
                            "title": f"Route origin changed for {ip}: AS{old_asn} → AS{asn}",
                            "detail": (
                                f"{ip} was previously announced by AS{old_asn} and is now announced by "
                                f"AS{asn} ({route.get('org', '')}). An unexpected origin-ASN change is a "
                                "primary indicator of a BGP hijack — verify this was an intentional "
                                "provider/ASN migration."
                            ),
                            "category": "rpki_origin_change",
                            "asn": asn,
                            "previous_asn": old_asn,
                            "ip": ip,
                        })
                        try:
                            from yads.core.webhook_service import webhook_service
                            from yads.models import Target as _Target
                            with _Session(_engine) as _db2:
                                t = _db2.get(_Target, target_id)
                            if t:
                                webhook_service.trigger_event(t.tenant_id, "security_alert", {
                                    "domain": domain,
                                    "module": "rpki_scanner",
                                    "severity": "critical",
                                    "title": f"Route origin changed for {ip}: AS{old_asn} → AS{asn}",
                                    "detail": f"Possible BGP hijack on {domain} ({ip}).",
                                })
                        except Exception as e:
                            logger.warning(f"[RPKI] Route-change webhook failed (non-fatal): {e}")
            except Exception as e:
                logger.warning(f"[RPKI] Route-origin monitoring failed: {e}")

        # Score
        score = 100
        for f in result["findings"]:
            if f["severity"] == "critical":
                score -= 40
            elif f["severity"] == "high":
                score -= 25
            elif f["severity"] == "medium":
                score -= 8
        result["summary"]["score"] = max(0, score)
        result["summary"]["findings_count"] = len(result["findings"])

        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_ips(self, domain: str) -> List[str]:
        ips: List[str] = []
        try:
            for r in socket.getaddrinfo(domain, None):
                ip = r[4][0]
                # skip IPv6 and loopback for now
                if ip not in ips and ":" not in ip and not ip.startswith("127."):
                    ips.append(ip)
        except Exception:
            pass
        return ips[:3]

    def _get_network_info(self, ip: str) -> Optional[Dict]:
        """RIPE Stat network-info: returns {asn, prefix}."""
        try:
            resp = throttled_get(
                f"{RIPE_STAT}/network-info/data.json",
                service="ripestat",
                params={"resource": ip},
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": "YADS Security Scanner"},
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                asns = data.get("asns", [])
                prefix = data.get("prefix", "")
                if asns and prefix:
                    asn = str(asns[0]).replace("AS", "")
                    org = self._get_org_name(asn)
                    return {"asn": asn, "prefix": prefix, "org": org, "country": ""}
        except Exception as e:
            logger.debug(f"[RPKI] network-info failed for {ip}: {e}")

        return self._get_asn_ipinfo(ip)

    def _get_org_name(self, asn: str) -> str:
        """RIPE Stat AS overview for org name."""
        try:
            resp = throttled_get(
                f"{RIPE_STAT}/as-overview/data.json",
                service="ripestat",
                params={"resource": f"AS{asn}"},
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": "YADS Security Scanner"},
            )
            if resp.status_code == 200:
                return resp.json().get("data", {}).get("holder", "")
        except Exception:
            pass
        return ""

    def _get_asn_ipinfo(self, ip: str) -> Optional[Dict]:
        """Fallback: ipinfo.io (free, no key needed for basic info)."""
        try:
            resp = throttled_get(
                f"https://ipinfo.io/{ip}/json",
                service="ipinfo",
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": "YADS Security Scanner"},
            )
            if resp.status_code != 200:
                return None
            d = resp.json()
            org_raw = d.get("org", "")
            asn, org = "", org_raw
            if org_raw.startswith("AS"):
                parts = org_raw.split(" ", 1)
                asn = parts[0].replace("AS", "")
                org = parts[1] if len(parts) > 1 else ""
            return {
                "asn": asn,
                "prefix": d.get("network", ""),
                "org": org,
                "country": d.get("country", ""),
            }
        except Exception:
            return None

    def _check_rpki(self, asn: str, prefix: str) -> Dict:
        """RIPE Stat RPKI validation for ASN+prefix."""
        try:
            resp = throttled_get(
                f"{RIPE_STAT}/rpki-validation/data.json",
                service="ripestat",
                params={"resource": f"AS{asn}", "prefix": prefix},
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": "YADS Security Scanner"},
            )
            if resp.status_code != 200:
                return {"state": "unknown", "roas": []}

            data = resp.json().get("data", {})
            raw_state = data.get("status", "unknown").lower()
            # RIPE returns: "valid", "invalid", "unknown" (= no ROA)
            state = "not_found" if raw_state == "unknown" else raw_state

            roas = [
                {
                    "prefix": r.get("prefix"),
                    "max_length": r.get("max_length"),
                    "origin_asn": r.get("origin_asn"),
                    "ta": r.get("ta"),
                }
                for r in data.get("validating_roas", [])
            ]
            return {"state": state, "roas": roas}
        except Exception as e:
            logger.debug(f"[RPKI] rpki-validation failed for AS{asn}/{prefix}: {e}")
            return {"state": "unknown", "roas": []}
