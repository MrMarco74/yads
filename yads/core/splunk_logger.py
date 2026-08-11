import os
import requests
import json
import time
import socket
import sys
import functools
import logging
from typing import Optional, Any, Dict

# Configure a local logger for fallback (STDERR)
logger = logging.getLogger("splunk_logger")
logger.setLevel(logging.ERROR)
handler = logging.StreamHandler(sys.stderr)
handler.setFormatter(logging.Formatter('%(asctime)s - SPLUNK_ERROR - %(message)s'))
logger.addHandler(handler)

class SplunkHECLogger:
    def __init__(self):
        self.host = socket.gethostname()
        self.verify_ssl = False  # Allow self-signed or internal CA certs
        self.token = None
        self.url = None
        self.enabled = False
        self._refresh_config()

    def _refresh_config(self) -> None:
        db_url = None
        db_token = None
        try:
             from yads.config import settings
             from yads.models import SystemConfig
             from sqlmodel import Session, create_engine
             
             engine = create_engine(settings.DATABASE_URL)
             with Session(engine) as session:
                 s_url = session.get(SystemConfig, "SPLUNK_HEC_URL")
                 if s_url and s_url.value: db_url = s_url.value
                 
                 s_token = session.get(SystemConfig, "SPLUNK_HEC_TOKEN")
                 if s_token and s_token.value: db_token = s_token.value
        except Exception:
             pass

        self.token = db_token if db_token else os.environ.get("SPLUNK_HEC_TOKEN")
        self.url = db_url if db_url else os.environ.get("SPLUNK_HEC_URL")

        if not self.token or not self.url:
            self.enabled = False
        else:
            self.enabled = True

    def _send_payload(self, payload: Dict[str, Any]) -> None:
        if not self.enabled:
            self._refresh_config()
            if not self.enabled:
                return

        headers = {
            "Authorization": f"Splunk {self.token}",
            "Content-Type": "application/json"
        }

        try:
            response = requests.post(
                self.url,
                headers=headers,
                data=json.dumps(payload),
                verify=self.verify_ssl,
                timeout=5  # Fast timeout to avoid blocking main thread too long
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            # Requirements: Log to STDERR, do not crash app
            logger.error(f"Failed to send event to Splunk: {e}")

    def send_event(self, data: Dict[str, Any], sourcetype: str = "json", tenant_id: Optional[int] = None) -> None:
        """
        Sends a generic event to Splunk.
        """
        if not self.enabled:
            return

        payload = {
            "time": time.time(),
            "host": self.host,
            "sourcetype": sourcetype,
            "event": data
        }
        
        # Inject Tenant ID if provided
        if tenant_id is not None:
            payload["event"]["tenant_id"] = tenant_id

        self._send_payload(payload)

    def send_security_event(self, action: str, user: str, mitre_id: str, details: Dict[str, Any] = None, tenant_id: Optional[int] = None) -> None:
        """
        Sends a structured Security Event compliant with common CIM fields and MITRE context.
        """
        if not self.enabled:
            return

        if details is None:
            details = {}

        # Construct Event Body
        event_data = {
            "action": action,
            "user": user,
            "mitre_tactic_id": "TA0000", # Placeholder or derived if needed
            "mitre_technique_id": mitre_id,
            "details": details,
            "app": "YADS"
        }
        
        if tenant_id is not None:
            event_data["tenant_id"] = tenant_id

        # Sending as 'yads:security' sourcetype for easy filtering
        self.send_event(event_data, sourcetype="yads:security")

# Singleton Instance (Lazy init can be done by modules importing this)
splunk_logger = SplunkHECLogger()

def mitre_audit(id: str):
    """
    Decorator to audit function calls.
    Logs the user (if present in kwargs or context) and the action.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Try to extract user from kwargs (common in FastAPI dependencies)
            user_obj = kwargs.get("user")
            username = "unknown"
            if user_obj and hasattr(user_obj, "username"):
                username = user_obj.username
            elif user_obj and isinstance(user_obj, dict):
                 username = user_obj.get("username", "unknown")
            
            # Extract details strictly from arguments to avoid huge dumps
            # We assume sensible arguments are passed.
            details = {
                "function": func.__name__,
                "module": func.__module__,
                "args_summary": str(args)[:200] # Truncate for sanity
            }

            # Send Audit Log
            splunk_logger.send_security_event(
                action="function_execution",
                user=username,
                mitre_id=id,
                details=details
            )

            # Execute actual function
            return func(*args, **kwargs)
        return wrapper
    return decorator
