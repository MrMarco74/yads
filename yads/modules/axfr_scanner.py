"""
DNS Zone Transfer Check (AXFR)
================================
Attempts AXFR zone transfer against all authoritative nameservers.
A successful transfer leaks the entire DNS zone — critical finding.
"""
import logging
from typing import Any, Dict, List, Optional

import dns.resolver
import dns.query
import dns.zone
import dns.exception

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

AXFR_TIMEOUT = 5


class AXFRScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "axfr_scanner"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        logger.info(f"[AXFR] Starting zone transfer check for {target}")
        nameservers = self._get_nameservers(target)
        results: List[Dict] = []
        vulnerable = False

        for ns in nameservers:
            ns_result = self._try_axfr(target, ns)
            results.append(ns_result)
            if ns_result["success"]:
                vulnerable = True

        finding = None
        if vulnerable:
            logger.warning(f"[AXFR] Zone transfer SUCCESSFUL for {target} — critical!")
            finding = {
                "severity": "critical",
                "issue": "DNS zone transfer (AXFR) is publicly allowed — full zone exposed",
                "recommendation": "Restrict AXFR to trusted IP ranges in nameserver config (BIND: allow-transfer)",
            }

        # Continuous monitoring (#70): nameserver config can change between scans
        # (a misconfigured secondary added, a firewall rule dropped), so this
        # module already reruns on every normal rescan cycle via ScanSchedule --
        # what was missing was an active alert on the moment it *newly* becomes
        # exploitable, rather than only a passive finding row. Diff against the
        # last-seen state (baseline_diff, Welle 0) and fire a webhook only on
        # the not-vulnerable -> vulnerable transition.
        if target_id:
            try:
                from yads.database import engine as _engine
                from sqlmodel import Session as _Session
                from yads.core.baseline_diff import diff_against_last
                from yads.core.webhook_service import WebhookService
                from yads.models import Target as _Target

                with _Session(_engine) as _db:
                    diff = diff_against_last(
                        _db, "axfr_vulnerable",
                        ["vulnerable"] if vulnerable else [],
                        target_id=target_id,
                    )
                    if "vulnerable" in diff["added"]:
                        t = _db.get(_Target, target_id)
                        if t:
                            WebhookService().trigger_event(t.tenant_id, "security_alert", {
                                "domain": target,
                                "module": "axfr_scanner",
                                "severity": "critical",
                                "title": "DNS zone transfer (AXFR) newly exposed",
                                "detail": finding["issue"] if finding else "",
                            })
            except Exception as e:
                logger.warning(f"[AXFR] Continuous-monitoring diff/webhook failed (non-fatal): {e}")

        return {
            "nameservers_checked": nameservers,
            "vulnerable": vulnerable,
            "transfer_results": results,
            "finding": finding,
        }

    def _get_nameservers(self, domain: str) -> List[str]:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 5.0
            answers = resolver.resolve(domain, "NS")
            ns_list = []
            for r in answers:
                ns_name = str(r).rstrip(".")
                try:
                    a_answers = resolver.resolve(ns_name, "A")
                    ns_list.append(str(a_answers[0]))
                except Exception:
                    ns_list.append(ns_name)
            return ns_list[:6]  # cap to avoid timeout storms
        except Exception as e:
            logger.warning(f"[AXFR] Failed to resolve NS records for {domain}: {e}")
            return []

    def _try_axfr(self, domain: str, ns: str) -> Dict:
        try:
            zone = dns.zone.from_xfr(
                dns.query.xfr(ns, domain, timeout=AXFR_TIMEOUT, lifetime=AXFR_TIMEOUT)
            )
            record_count = sum(1 for _ in zone.iterate_rdatasets())
            records_preview = []
            for name, node in zone.nodes.items():
                records_preview.append(str(name))
                if len(records_preview) >= 20:
                    break
            return {
                "nameserver": ns,
                "success": True,
                "record_count": record_count,
                "records_preview": records_preview,
            }
        except dns.exception.FormError:
            # AXFR refused — expected for secure configs
            return {"nameserver": ns, "success": False, "reason": "AXFR refused"}
        except Exception as e:
            return {"nameserver": ns, "success": False, "reason": str(e)[:120]}
