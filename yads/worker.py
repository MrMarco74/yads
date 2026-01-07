from celery import Celery
from sqlmodel import Session, create_engine, select
from yads.models import ScanResult, Target
from datetime import datetime
import os

from yads.config import settings
from yads.core.logging_config import configure_logging
from yads.modules.dns_scanner import DNSScanner
from yads.modules.web_analyzer import WebAnalyzer
from yads.modules.visual_osint import VisualOSINT

# Configure Logging
logger = configure_logging("yads-worker")

# Initialize Celery
celery_app = Celery("yads_worker", broker=settings.REDIS_URL, backend=settings.REDIS_URL)

# Database access for worker
engine = create_engine(settings.DATABASE_URL)

import io


import logging

class LogCapture:
    """
    Context manager to capture logs to a string.
    """
    def __init__(self):
        self.log_stream = io.StringIO()
        self.handler = logging.StreamHandler(self.log_stream)
        self.handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)-15s | %(message)s"))
    
    def __enter__(self):
        # Attach to root logger to capture everything
        logging.getLogger().addHandler(self.handler)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        logging.getLogger().removeHandler(self.handler)
        self.handler.close()

    def get_logs(self):
        return self.log_stream.getvalue()


@celery_app.task(name="yads.worker.run_all_scans")
def run_all_scans(target_id: int, domain: str, scan_types: list[str] = None):
    """
    Main orchestration task.
    Runs configured scanners for the given target.
    If scan_types is None, runs all available scanners.
    """
    if scan_types is None:
        scan_types = ["dns_scanner", "web_analyzer", "typosquat_scanner", "infrastructure_scanner", "visual_osint"]
        
    print(f"[Worker] Starting scan for {domain} (ID: {target_id}) with types: {scan_types}")
    
    with Session(engine) as session:
        # Update Status to Running
        try:
            target = session.get(Target, target_id)
            if target:
                target.scan_status = "running"
                target.scan_progress = "Initializing scan..."
                session.add(target)
                session.commit()
        except Exception as e:
            print(f"[Worker] Failed to update start status: {e}")

        # 1. Run DNS Scanner
        if "dns_scanner" in scan_types:
            try:
                dns = DNSScanner(db_session=session)
                print(f"[Worker] Running {dns.module_name}...")
                
                with LogCapture() as logs:
                    logger.info(f"Starting {dns.module_name} for {domain}")
                    result = dns.process(target_id, domain)
                    captured_logs = logs.get_logs()
                
                if result:
                    print(f"[Worker] {dns.module_name} found changes/new data.")
                    # Update the ScanResult with logs if it was created/returned
                    # Note: process() returns the ScanResult object (or ModuleState if no change? Access pattern differs)
                    # The scan modules usually commit inside process(). We need to fetch the last Result.
                    # Ideally process() should return the Result object.
                    # Looking at dns_scanner.py, process() returns the ScanResult or None.
                    if isinstance(result, object) and hasattr(result, 'log_content'):
                         result.log_content = captured_logs
                         session.add(result)
                         session.commit()

                else:
                     print(f"[Worker] {dns.module_name} no change.")
            except Exception as e:
                print(f"[Worker] Error in DNS Scanner: {e}")
            except Exception as e:
                print(f"[Worker] Error in DNS Scanner: {e}")

        # 2. Run Web Scanner
        if "web_analyzer" in scan_types:
            try:
                t = session.get(Target, target_id)
                if t:
                    t.scan_progress = "Running Web Analyzer..."
                    session.add(t)
                    session.commit()

                web = WebAnalyzer(db_session=session)
                print(f"[Worker] Running {web.module_name}...")
                with LogCapture() as logs:
                    logger.info(f"Starting {web.module_name} for {domain}")
                    result = web.process(target_id, domain)
                    captured_logs = logs.get_logs()
                
                if result and hasattr(result, 'log_content'):
                     result.log_content = captured_logs
                     session.add(result)
                     session.commit()
                     print(f"[Worker] {web.module_name} found changes/new data.")
                else:
                     print(f"[Worker] {web.module_name} no change.")
            except Exception as e:
                print(f"[Worker] Error in Web Analyzer: {e}")

        # 3. Run Typosquat Scanner
        if "typosquat_scanner" in scan_types:
            try:
                t = session.get(Target, target_id)
                if t:
                    t.scan_progress = "Running Typosquat Scanner..."
                    session.add(t)
                    session.commit()

                from yads.modules.typosquat_scanner import TyposquatScanner
                ts = TyposquatScanner(db_session=session)
                print(f"[Worker] Running {ts.module_name}...")
                with LogCapture() as logs:
                    logger.info(f"Starting {ts.module_name} for {domain}")
                    result = ts.process(target_id, domain)
                    captured_logs = logs.get_logs()
                
                if result and hasattr(result, 'log_content'):
                     result.log_content = captured_logs
                     session.add(result)
                     session.commit()
                     print(f"[Worker] {ts.module_name} found changes/new data.")
                else:
                     print(f"[Worker] {ts.module_name} no change.")
            except Exception as e:
                print(f"[Worker] Error in Typosquat Scanner: {e}")

        # 4. Run Infrastructure Scanner
        if "infrastructure_scanner" in scan_types:
            try:
                t = session.get(Target, target_id)
                if t:
                    t.scan_progress = "Running Infrastructure Scanner..."
                    session.add(t)
                    session.commit()

                from yads.modules.infrastructure_scanner import InfrastructureScanner
                inf = InfrastructureScanner(db_session=session)
                print(f"[Worker] Running {inf.module_name}...")
                with LogCapture() as logs:
                    logger.info(f"Starting {inf.module_name} for {domain}")
                    result = inf.process(target_id, domain)
                    captured_logs = logs.get_logs()
                
                if result and hasattr(result, 'log_content'):
                     result.log_content = captured_logs
                     session.add(result)
                     session.commit()
                     print(f"[Worker] {inf.module_name} found changes/new data.")
                else:
                     print(f"[Worker] {inf.module_name} no change.")
            except Exception as e:
                print(f"[Worker] Error in Infrastructure Scanner: {e}")

        # 5. Run Visual OSINT
        if "visual_osint" in scan_types:
            try:
                t = session.get(Target, target_id)
                if t:
                    t.scan_progress = "Running Visual OSINT..."
                    session.add(t)
                    session.commit()

                from yads.modules.visual_osint import VisualOSINT
                vis = VisualOSINT(db_session=session)
                print(f"[Worker] Running {vis.module_name}...")
                with LogCapture() as logs:
                    logger.info(f"Starting {vis.module_name} for {domain}")
                    result = vis.process(target_id, domain)
                    captured_logs = logs.get_logs()
                
                if result and hasattr(result, 'log_content'):
                     result.log_content = captured_logs
                     session.add(result)
                     session.commit()
                     print(f"[Worker] {vis.module_name} found changes/new data.")
                else:
                     print(f"[Worker] {vis.module_name} no change.")
            except Exception as e:
                print(f"[Worker] Error in Visual OSINT: {e}")
            except Exception as e:
                print(f"[Worker] Error in Visual OSINT: {e}")
    
        # Reset status
        try:
             # Refresh session or re-fetch?
             t = session.get(Target, target_id)
             if t:
                 t.scan_status = "idle"
                 t.scan_progress = f"Last scan completed at {datetime.utcnow().strftime('%H:%M:%S')}"
                 session.add(t)
                 session.commit()
        except Exception as e:
             print(f"[Worker] Failed to update finish status: {e}")

    print(f"[Worker] Finished scan for {domain}")
