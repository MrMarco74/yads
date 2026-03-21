import ipaddress
import logging
import socket
from urllib.parse import urlparse

import requests
from sqlmodel import Session, select

from yads.database import engine
from yads.models import Webhook

logger = logging.getLogger(__name__)

# Private/link-local ranges that webhooks must never reach
_BLOCKED_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / AWS metadata
    ipaddress.ip_network("100.64.0.0/10"),    # Carrier-grade NAT
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]
_BLOCKED_HOSTS = frozenset({
    "169.254.169.254",         # AWS / GCP / Azure metadata
    "metadata.google.internal",
    "169.254.170.2",           # AWS ECS task metadata
    "100.100.100.200",         # Alibaba Cloud metadata
})


def _validate_webhook_url(url: str) -> None:
    """Reject SSRF targets — private IPs, link-local, and cloud metadata endpoints."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Webhook URL must use http or https, got: {parsed.scheme!r}")
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if hostname in _BLOCKED_HOSTS:
        raise ValueError(f"Webhook URL hostname is blocked: {hostname!r}")
    try:
        addr = ipaddress.ip_address(hostname)
        for net in _BLOCKED_NETS:
            if addr in net:
                raise ValueError(f"Webhook URL resolves to a private/reserved address: {addr}")
    except ValueError as exc:
        if "blocked" in str(exc) or "private" in str(exc):
            raise
        # hostname — do a DNS lookup and check the resolved IP
        try:
            resolved = socket.gethostbyname(hostname)
            addr = ipaddress.ip_address(resolved)
            for net in _BLOCKED_NETS:
                if addr in net:
                    raise ValueError(f"Webhook URL '{hostname}' resolves to private IP {addr}")
        except socket.gaierror:
            pass  # DNS failure — let requests() handle it naturally


class WebhookService:
    def trigger_event(self, tenant_id: int, event_type: str, payload: dict):
        """
        Triggers all active webhooks for a given tenant and event type.
        """
        logger.info(f"Triggering webhook event '{event_type}' for tenant {tenant_id}")
        
        try:
            with Session(engine) as session:
                # Fetch active webhooks for this tenant
                webhooks = session.exec(select(Webhook).where(
                    Webhook.tenant_id == tenant_id,
                    Webhook.is_active == True
                )).all()
                
                triggered_count = 0
                for hook in webhooks:
                    # Check if this hook is subscribed to the event
                    # event_types is stored as JSON list
                    if event_type in hook.event_types:
                        self._send_payload(hook.url, event_type, payload)
                        triggered_count += 1
                
                logger.info(f"Sent {triggered_count} webhooks for tenant {tenant_id}")
                        
        except Exception as e:
            logger.error(f"Error triggering webhooks: {e}")

    def trigger_osint_alert(self, payload: dict):
        """
        Triggers the global OSINT webhook defined in SystemConfig.
        """
        logger.info("Triggering global OSINT webhook alert")
        try:
            from yads.models import SystemConfig
            with Session(engine) as session:
                osint_url_record = session.get(SystemConfig, "OSINT_WEBHOOK_URL")
                if not osint_url_record or not osint_url_record.value:
                    return
                
                url = osint_url_record.value.strip()
                if url:
                    self._send_payload(url, "osint_alert", payload)
        except Exception as e:
            logger.error(f"Error triggering OSINT webhook: {e}")

    def _send_payload(self, url: str, event_type: str, data: dict):
        """
        Sends the actual HTTP POST request.
        """
        try:
            _validate_webhook_url(url)
        except ValueError as e:
            logger.error(f"Webhook URL blocked (SSRF protection): {e}")
            return

        payload = {
            "event": event_type,
            "timestamp": data.get("timestamp") or "now",
            "data": data
        }

        try:
            headers = {"Content-Type": "application/json", "User-Agent": "YADS-Webhook/1.0"}
            response = requests.post(url, json=payload, headers=headers, timeout=5)
            
            if response.status_code >= 200 and response.status_code < 300:
                logger.info(f"Webhook delivered to {url} (Status: {response.status_code})")
            else:
                logger.warning(f"Webhook failed for {url} (Status: {response.status_code}): {response.text}")
                
        except requests.RequestException as e:
            logger.error(f"Webhook delivery failed for {url}: {e}")

# Global instance
webhook_service = WebhookService()
