"""
DNS Cleanup Scanner Module

Identifies dead DNS entries (domains without A/AAAA records) and archives them.
"""

from yads.core.base import BaseScanner
from yads.models import Target
import dns.resolver
import logging

logger = logging.getLogger(__name__)


class DNSCleanupScanner(BaseScanner):
    """
    Scans targets to identify dead DNS entries.
    Archives targets that don't resolve to any IP address.
    """
    
    @property
    def module_name(self) -> str:
        return "dns_cleanup"
    
    def process(self, target_id: int, domain: str):
        """
        Check if domain resolves to any IP.
        If not, mark as archived with reason 'dns_dead'.
        
        Returns:
            ScanResult if target was archived, None otherwise
        """
        from yads.models import ScanResult
        from datetime import datetime
        
        logger.info(f"[DNSCleanup] Checking DNS resolution for {domain}")
        
        # Check DNS resolution
        has_a_record = False
        has_aaaa_record = False
        
        try:
            dns.resolver.resolve(domain, 'A')
            has_a_record = True
            logger.info(f"[DNSCleanup] {domain} has A record")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            logger.info(f"[DNSCleanup] {domain} has no A record")
        except Exception as e:
            logger.warning(f"[DNSCleanup] Error checking A record for {domain}: {e}")
        
        try:
            dns.resolver.resolve(domain, 'AAAA')
            has_aaaa_record = True
            logger.info(f"[DNSCleanup] {domain} has AAAA record")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            logger.info(f"[DNSCleanup] {domain} has no AAAA record")
        except Exception as e:
            logger.warning(f"[DNSCleanup] Error checking AAAA record for {domain}: {e}")
        
        # Determine if target is dead
        is_dead = not (has_a_record or has_aaaa_record)
        
        if is_dead:
            # Archive the target
            target = self.db_session.get(Target, target_id)
            if target and not target.is_archived:
                target.is_archived = True
                target.archived_at = datetime.utcnow()
                target.archived_reason = "dns_dead"
                self.db_session.add(target)
                self.db_session.commit()
                
                logger.warning(f"[DNSCleanup] Archived {domain} - no DNS resolution")
                
                # Trigger webhook event
                from yads.core.webhook_service import webhook_service
                webhook_service.trigger_event(target.tenant_id, "target_archived", {
                    "domain": domain,
                    "reason": "dns_dead",
                    "archived_at": target.archived_at.isoformat()
                })
                
                # Create scan result for history
                result_data = {
                    "status": "dead",
                    "has_a_record": has_a_record,
                    "has_aaaa_record": has_aaaa_record,
                    "action": "archived"
                }
                
                result = ScanResult(
                    target_id=target_id,
                    module_name=self.module_name,
                    data=result_data,
                    result_hash=self.hash_result(result_data)
                )
                
                return result
        else:
            logger.info(f"[DNSCleanup] {domain} is alive (has DNS records)")
            
            # If target was previously archived but now resolves, unarchive it
            target = self.db_session.get(Target, target_id)
            if target and target.is_archived and target.archived_reason == "dns_dead":
                target.is_archived = False
                target.archived_at = None
                target.archived_reason = None
                self.db_session.add(target)
                self.db_session.commit()
                
                logger.info(f"[DNSCleanup] Restored {domain} - DNS now resolves")
                
                # Trigger webhook event
                from yads.core.webhook_service import webhook_service
                webhook_service.trigger_event(target.tenant_id, "target_restored", {
                    "domain": domain,
                    "reason": "dns_alive"
                })
        
        return None
