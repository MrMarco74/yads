"""
DNS Cleanup Scanner Module

Identifies dead DNS entries (domains without A/AAAA records) and archives them.
"""

from yads.core.base import BaseScannerModule
from yads.models import Target
import dns.resolver
import dns.exception
import logging
import time
from typing import Optional, Dict, Tuple

logger = logging.getLogger(__name__)

# Number of retries for transient DNS failures
DNS_RETRY_COUNT = 3
DNS_RETRY_DELAY = 2  # seconds between retries


class DNSCleanupScanner(BaseScannerModule):
    """
    Scans targets to identify dead DNS entries.
    Archives targets that don't resolve to any IP address.
    Only archives when DNS definitively returns NXDOMAIN (domain doesn't exist).
    Transient errors are NOT treated as dead domains.
    """

    @property
    def module_name(self) -> str:
        return "dns_cleanup"

    def _resolve_with_retry(self, domain: str, record_type: str) -> Tuple[bool, bool, str]:
        """
        Resolve DNS with retry logic.

        Returns:
            Tuple of (has_record, is_definitive, reason)
            - has_record: True if record exists
            - is_definitive: True if we got a definitive answer (not a transient failure)
            - reason: Description of result
        """
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5.0  # 5 second timeout per query
        resolver.lifetime = 10.0  # 10 second total lifetime

        last_error = None

        for attempt in range(DNS_RETRY_COUNT):
            try:
                resolver.resolve(domain, record_type)
                return (True, True, f"has {record_type} record")
            except dns.resolver.NXDOMAIN:
                # Domain definitively doesn't exist - no need to retry
                return (False, True, f"NXDOMAIN - domain does not exist")
            except dns.resolver.NoAnswer:
                # Domain exists but has no record of this type - definitive
                return (False, True, f"no {record_type} record (NoAnswer)")
            except dns.resolver.NoNameservers:
                # No nameservers - could be transient, retry
                last_error = f"NoNameservers on attempt {attempt + 1}"
                logger.warning(f"[DNSCleanup] {domain} {record_type}: {last_error}")
            except dns.exception.Timeout:
                # Timeout - transient, retry
                last_error = f"Timeout on attempt {attempt + 1}"
                logger.warning(f"[DNSCleanup] {domain} {record_type}: {last_error}")
            except Exception as e:
                # Unknown error - transient, retry
                last_error = f"Error on attempt {attempt + 1}: {e}"
                logger.warning(f"[DNSCleanup] {domain} {record_type}: {last_error}")

            if attempt < DNS_RETRY_COUNT - 1:
                time.sleep(DNS_RETRY_DELAY)

        # All retries exhausted - treat as inconclusive (NOT dead)
        return (False, False, f"inconclusive after {DNS_RETRY_COUNT} attempts: {last_error}")

    def run_scan(self, domain: str, target_id: Optional[int] = None) -> Dict:
        """
        Check if domain resolves to any IP.
        Only archives if DNS definitively returns NXDOMAIN or NoAnswer for both A and AAAA.
        Transient failures (timeouts, network errors) are NOT treated as dead domains.
        """
        from datetime import datetime

        logger.info(f"[DNSCleanup] Checking DNS resolution for {domain}")

        # Check DNS resolution with retry logic
        has_a, a_definitive, a_reason = self._resolve_with_retry(domain, 'A')
        has_aaaa, aaaa_definitive, aaaa_reason = self._resolve_with_retry(domain, 'AAAA')

        logger.info(f"[DNSCleanup] {domain} A: {a_reason}")
        logger.info(f"[DNSCleanup] {domain} AAAA: {aaaa_reason}")
        
        # Determine if target is definitively dead
        # Only mark as dead if BOTH queries are definitive AND neither has records
        is_definitive = a_definitive and aaaa_definitive
        has_any_record = has_a or has_aaaa
        is_dead = is_definitive and not has_any_record

        result_data = {
            "status": "dead" if is_dead else ("alive" if has_any_record else "inconclusive"),
            "has_a_record": has_a,
            "has_aaaa_record": has_aaaa,
            "a_check_definitive": a_definitive,
            "aaaa_check_definitive": aaaa_definitive,
            "a_reason": a_reason,
            "aaaa_reason": aaaa_reason,
            "action": "none"
        }

        if is_dead:
            # Archive the target - only when definitively confirmed as dead
            target = self.db.get(Target, target_id)
            if target and not target.is_archived:
                target.is_archived = True
                target.archived_at = datetime.utcnow()
                target.archived_reason = "dns_dead"
                self.db.add(target)
                self.db.commit()

                logger.warning(f"[DNSCleanup] Archived {domain} - definitively no DNS resolution")
                result_data["action"] = "archived"

                # Trigger webhook event
                from yads.core.webhook_service import webhook_service
                webhook_service.trigger_event(target.tenant_id, "target_archived", {
                    "domain": domain,
                    "reason": "dns_dead",
                    "archived_at": target.archived_at.isoformat()
                })
        elif has_any_record:
            logger.info(f"[DNSCleanup] {domain} is alive (has DNS records)")

            # If target was previously archived but now resolves, unarchive it
            target = self.db.get(Target, target_id)
            if target and target.is_archived and target.archived_reason == "dns_dead":
                target.is_archived = False
                target.archived_at = None
                target.archived_reason = None
                self.db.add(target)
                self.db.commit()

                logger.info(f"[DNSCleanup] Restored {domain} - DNS now resolves")
                result_data["action"] = "restored"

                # Trigger webhook event
                from yads.core.webhook_service import webhook_service
                webhook_service.trigger_event(target.tenant_id, "target_restored", {
                    "domain": domain,
                    "reason": "dns_alive"
                })
        else:
            # Inconclusive - don't archive, don't restore, just log
            logger.warning(f"[DNSCleanup] {domain} DNS check inconclusive - not archiving (transient failure)")

        return result_data
