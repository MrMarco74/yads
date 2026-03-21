"""
worker_modules.py — Scanner module runner helpers and LogCapture.

Re-exported via yads/worker.py for backwards compatibility.
"""
import io
import os
import socket
import ipaddress
from sqlmodel import Session

from yads.worker_core import logger
from yads.config import settings
from yads.database import engine


class LogCapture:
    """Context manager to capture logs to a string."""

    def __init__(self):
        self.log_stream = io.StringIO()
        self.handler = logging.StreamHandler(self.log_stream)
        self.handler.setFormatter(
            logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)-15s | %(message)s")
        )

    def __enter__(self):
        logging.getLogger().addHandler(self.handler)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        logging.getLogger().removeHandler(self.handler)
        self.handler.close()

    def get_logs(self):
        return self.log_stream.getvalue()


def validate_target_safety(domain: str) -> bool:
    """
    Defense-in-depth SSRF protection.
    Verifies that the target domain does not resolve to a private or reserved IP address.
    Returns True if safe, False if unsafe/blocked.
    """
    if os.getenv("ALLOW_INTERNAL_SCANNING", "").lower() == "true":
        return True

    try:
        # 1. Check if domain itself is an IP
        try:
            ip = ipaddress.ip_address(domain)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                logger.warning(f"[Worker] Blocked internal IP target: {domain}")
                return False
        except ValueError:
            pass # Not an IP, continue to DNS resolution

        # 2. Resolve DNS and check all returned IPs
        ips = socket.getaddrinfo(domain, None)
        for family, kind, proto, canonname, sockaddr in ips:
            ip_str = sockaddr[0]
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                logger.warning(f"[Worker] Blocked target {domain} resolving to internal IP: {ip_str}")
                return False
                
        return True
    except Exception as e:
        logger.error(f"[Worker] Failed to validate target safety for {domain}: {e}")
        # Fail safe: block if we can't verify
        return False


def _run_parallel_module(module_cls, target_id: int, domain: str):
    """
    Run a scanner module in its own DB session (thread-safe parallel execution).
    Each parallel module gets an isolated session; results are committed independently.
    LogCapture is intentionally skipped to avoid root-logger thread-safety issues —
    logs still flow via the Redis handler attached by the parent task.
    """
    from yads.utils.sanitize import sanitize_null_bytes
    try:
        # SSRF Protection (Defense-in-Depth)
        if not validate_target_safety(domain):
            logger.error(f"[Worker] SSRF Protection: Skipping parallel module {module_cls.__name__} for unsafe target {domain}")
            return

        with Session(engine) as session:
            mod = module_cls(db_session=session)
            result = mod.process(target_id, domain)
            if result and hasattr(result, 'log_content'):
                session.add(result)
                session.commit()
            logger.info(f"[Worker] Parallel: {mod.module_name} finished.")
    except Exception as e:
        logger.error(f"[Worker] Parallel module {module_cls.__name__} error: {e}")


def _run_simple_module(module_cls, target_id: int, domain: str, session, progress_msg: str = None):
    """
    DRY helper for simple scanner modules.
    Updates scan_progress, runs module, saves log_content.
    Returns True on success, False on error.
    """
    from yads.models import Target
    from yads.utils.sanitize import sanitize_null_bytes

    if progress_msg:
        t = session.get(Target, target_id)
        if t:
            t.scan_progress = progress_msg
            session.add(t)
            session.commit()
    try:
        # SSRF Protection (Defense-in-Depth)
        if not validate_target_safety(domain):
            logger.error(f"[Worker] SSRF Protection: Skipping simple module {module_cls.__name__} for unsafe target {domain}")
            return

        scanner = module_cls(db_session=session)
        logger.info(f"[Worker] Running {scanner.module_name}...")
        with LogCapture() as logs:
            logger.info(f"Starting {scanner.module_name} for {domain}")
            result = scanner.process(target_id, domain)
            captured_logs = logs.get_logs()
        if result and hasattr(result, 'log_content'):
            result.log_content = sanitize_null_bytes(captured_logs)
            session.add(result)
            session.commit()
        print(f"[Worker] {scanner.module_name} finished.")
        return True
    except Exception as e:
        logger.error(f"[Worker] Error in {module_cls.__name__}: {e}")
        session.rollback()
        return False
