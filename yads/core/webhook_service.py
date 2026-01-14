import requests
import logging
import json
from sqlmodel import Session, select
from yads.database import engine
from yads.models import Webhook

logger = logging.getLogger(__name__)

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

    def _send_payload(self, url: str, event_type: str, data: dict):
        """
        Sends the actual HTTP POST request.
        """
        payload = {
            "event": event_type,
            "timestamp": data.get("timestamp") or "now",
            "data": data
        }
        
        try:
            # Simple retry mechanism could be added here
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
