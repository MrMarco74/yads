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

import threading
import queue

class SplunkHECLogger:
    def __init__(self):
        self.host = socket.gethostname()
        self.verify_ssl = False  # Allow self-signed or internal CA certs
        self.token = None
        self.url = None
        self.enabled = False
        self._queue = queue.Queue(maxsize=5000)
        self._worker_thread = None
        self._refresh_config()
        self._start_worker()

    def _start_worker(self) -> None:
        if self._worker_thread is None or not self._worker_thread.is_alive():
            self._worker_thread = threading.Thread(target=self._queue_worker, daemon=True)
            self._worker_thread.start()

    def _queue_worker(self) -> None:
        while True:
            try:
                payload = self._queue.get(timeout=2.0)
                if payload is None:
                    break
                self._send_payload(payload)
                self._queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error in Splunk queue worker: {e}")

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
        if not self.token or not self.url:
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
                timeout=5
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send event to Splunk: {e}")

    def send_event(self, data: Dict[str, Any], sourcetype: str = "json", tenant_id: Optional[int] = None) -> None:
        """
        Pushes an event asynchronously into the Splunk HEC queue.
        """
        if not self.enabled:
            self._refresh_config()
            if not self.enabled:
                return

        payload = {
            "time": time.time(),
            "host": self.host,
            "sourcetype": sourcetype,
            "event": data
        }
        
        if tenant_id is not None:
            payload["event"]["tenant_id"] = tenant_id

        try:
            self._queue.put_nowait(payload)
        except queue.Full:
            logger.error("Splunk queue is full. Dropping event.")

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

    def send_ops_event(self, category: str, message: str, details: Dict[str, Any] = None, tenant_id: Optional[int] = None) -> None:
        """
        Sends Operational/System Health events (sourcetype: yads:ops).
        """
        if not self.enabled:
            return

        if details is None:
            details = {}

        event_data = {
            "category": category,
            "message": message,
            "details": details,
            "app": "YADS"
        }
        self.send_event(event_data, sourcetype="yads:ops", tenant_id=tenant_id)

    def send_finding_event(self, finding_type: str, domain: str, severity: str, details: Dict[str, Any] = None, mitre_id: str = "T1595.002", tenant_id: Optional[int] = None) -> None:
        """
        Sends Vulnerability / Recon Finding events (sourcetype: yads:finding).
        """
        if not self.enabled:
            return

        if details is None:
            details = {}

        event_data = {
            "finding_type": finding_type,
            "domain": domain,
            "severity": severity,
            "mitre_technique_id": mitre_id,
            "details": details,
            "app": "YADS"
        }
        self.send_event(event_data, sourcetype="yads:finding", tenant_id=tenant_id)

    def test_connection(self, url: str, token: str) -> tuple[bool, str]:
        """
        Sends a synchronous test payload to verify Splunk HEC reachability and token validity.
        """
        if not url or not token:
            return False, "URL and Token are required"

        headers = {
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json"
        }
        payload = {
            "time": time.time(),
            "host": self.host,
            "sourcetype": "yads:test",
            "event": {"message": "YADS Splunk HEC Connection Test", "status": "ok"}
        }

        try:
            resp = requests.post(url, headers=headers, data=json.dumps(payload), verify=self.verify_ssl, timeout=5)
            if resp.status_code == 200:
                return True, "Successfully connected to Splunk HEC!"
            else:
                return False, f"Splunk returned HTTP {resp.status_code}: {resp.text[:200]}"
        except requests.exceptions.RequestException as e:
            return False, f"Connection failed: {str(e)}"

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
