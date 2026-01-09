from celery import Celery
from sqlmodel import Session, create_engine, select
from yads.models import ScanResult, Target
from datetime import datetime
import os
import dns.resolver

from yads.config import settings
from yads.core.logging_config import configure_logging
from yads.modules.dns_scanner import SubdomainScanner, DNSRecordScanner
from yads.modules.web_analyzer import WebAnalyzer
from yads.modules.visual_osint import VisualOSINT

# Configure Logging
logger = configure_logging("yads-worker")

# Initialize Celery
celery_app = Celery("yads_worker", broker=settings.REDIS_URL, backend=settings.REDIS_URL)
celery_app.conf.worker_hijack_root_logger = False

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


import socket

@celery_app.task(name="yads.worker.run_all_scans")
def run_all_scans(target_id: int, domain: str, scan_types: list[str] = None):
    """
    Main orchestration task.
    Runs configured scanners for the given target.
    If scan_types is None, runs all available scanners.
    """
    if scan_types is None:
        # Default includes 'subdomain_scanner' (heavy) which covers DNS records too.
        scan_types = ["subdomain_scanner", "web_analyzer", "typosquat_scanner", "infrastructure_scanner", "visual_osint", "ssl_scanner", "wayback_scanner", "crawler", "content_discovery"]
        
    logger.info(f"[Worker] Starting scan for {domain} (ID: {target_id}) with types: {scan_types}")

    def check_port(host, port, timeout=2):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except:
            return False

    # Setup Redis Logging
    from yads.core.redis_logger import RedisLogHandler
    redis_handler = RedisLogHandler(target_id)
    # Be more specific with logger format for UI
    redis_handler.setFormatter(logging.Formatter("%(message)s"))
    
    # Attach to root logger to capture everything during this task
    # We use a try/finally block around the entire scan logic to ensure removal
    root_logger = logging.getLogger()
    root_logger.addHandler(redis_handler)

    try:
        with Session(engine) as session:
            # Update Status to Running
            try:
                target = session.get(Target, target_id)
                if not target:
                    logger.warning(f"[Worker] Target {domain} (ID: {target_id}) not found in DB. Aborting scan.")
                    return

                target.scan_status = "running"
                target.scan_progress = "Initializing scan..."
                session.add(target)
                session.commit()
            except Exception as e:
                logger.error(f"[Worker] Failed to update start status: {e}")
                session.rollback()
                return

            # Pre-check web availability to skip heavy web scans if offline
            has_http = False
            has_https = False
            
            # Only perform checks if web modules are requested
            if any(x in scan_types for x in ["web_analyzer", "visual_osint", "ssl_scanner"]):
                logger.info(f"[Worker] Pre-checking web ports for {domain}...")
                has_http = check_port(domain, 80)
                has_https = check_port(domain, 443)
                logger.info(f"[Worker] Web Pre-check: HTTP={has_http}, HTTPS={has_https}")

            # 1. Run Subdomain Scanner (Heavy)
            # Replaces old "dns_scanner" logic for full enumeration
            if "subdomain_scanner" in scan_types:
                try:
                    t = session.get(Target, target_id)
                    if t:
                        t.scan_progress = "Running Subdomain Scanner..."
                        session.add(t)
                        session.commit()

                    from yads.modules.dns_scanner import SubdomainScanner
                    # Only use crt.sh if SSL Scanner is also selected (per user request)
                    use_ct = "ssl_scanner" in scan_types
                    sub_scan = SubdomainScanner(db_session=session, use_ct_logs=use_ct)
                    logger.info(f"[Worker] Running {sub_scan.module_name} (CRT.sh: {use_ct})...")
                    
                    with LogCapture() as logs:
                        logger.info(f"Starting {sub_scan.module_name} for {domain}")
                        result = sub_scan.process(target_id, domain)
                        captured_logs = logs.get_logs()
                    
                    if result:
                        print(f"[Worker] {sub_scan.module_name} found changes/new data.")
                        if isinstance(result, object) and hasattr(result, 'log_content'):
                             result.log_content = captured_logs
                             session.add(result)
                             session.commit()
                    else:
                         print(f"[Worker] {sub_scan.module_name} no change.")
                except Exception as e:
                    logger.error(f"[Worker] Error in Subdomain Scanner: {e}")
                    session.rollback()

            # 1b. Run DNS Record Scanner (Light)
            if "dns_scanner" in scan_types:
                try:
                    t = session.get(Target, target_id)
                    if t:
                        t.scan_progress = "Running DNS Record Scanner..."
                        session.add(t)
                        session.commit()

                    from yads.modules.dns_scanner import DNSRecordScanner
                    dns_scan = DNSRecordScanner(db_session=session)
                    logger.info(f"[Worker] Running {dns_scan.module_name}...")
                    
                    with LogCapture() as logs:
                        logger.info(f"Starting {dns_scan.module_name} for {domain}")
                        result = dns_scan.process(target_id, domain)
                        captured_logs = logs.get_logs()
                    
                    if result and hasattr(result, 'log_content'):
                         result.log_content = captured_logs
                         session.add(result)
                         session.commit()
                except Exception as e:
                    logger.error(f"[Worker] Error in DNS Record Scanner: {e}")
                    session.rollback()

            # 2. Run Web Scanner
            # Dependency: CVE Scanner requires Web Analyzer
            if "cve_scanner" in scan_types and "web_analyzer" not in scan_types:
                 logger.info("[Worker] Auto-enabling Web Analyzer for CVE Scanner dependency.")
                 scan_types.append("web_analyzer")

            if "web_analyzer" in scan_types:
                if not (has_http or has_https):
                    logger.info("[Worker] Skipping Web Analyzer: Port 80/443 closed (Optimization).")
                else:
                    try:
                        t = session.get(Target, target_id)
                        if t:
                            t.scan_progress = "Running Web Analyzer..."
                            session.add(t)
                            session.commit()

                        enable_cves = "cve_scanner" in scan_types
                        web = WebAnalyzer(db_session=session, enable_cves=enable_cves)
                        logger.info(f"[Worker] Step 2: Running {web.module_name}...")
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
                        logger.error(f"[Worker] Error in Web Analyzer: {e}")
                        session.rollback()

            # 3. Run Typosquat Scanner (Independent of Web)
            if "typosquat_scanner" in scan_types:
                try:
                    t = session.get(Target, target_id)
                    if t:
                        t.scan_progress = "Running Typosquat Scanner..."
                        session.add(t)
                        session.commit()

                    from yads.modules.typosquat_scanner import TyposquatScanner
                    ts = TyposquatScanner(db_session=session)
                    logger.info(f"[Worker] Step 3: Running {ts.module_name}...")
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
                    logger.error(f"[Worker] Error in Typosquat Scanner: {e}")
                    session.rollback()

            # 4. Run Infrastructure Scanner (Independent)
            if "infrastructure_scanner" in scan_types:
                try:
                    t = session.get(Target, target_id)
                    if t:
                        t.scan_progress = "Running Infrastructure Scanner..."
                        session.add(t)
                        session.commit()

                    from yads.modules.infrastructure_scanner import InfrastructureScanner
                    inf = InfrastructureScanner(db_session=session)
                    logger.info(f"[Worker] Step 4: Running {inf.module_name}...")
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
                    logger.error(f"[Worker] Error in Infrastructure Scanner: {e}")
                    session.rollback()

            # 5. Run Visual OSINT
            if "visual_osint" in scan_types:
                if not (has_http or has_https):
                    logger.info("[Worker] Skipping Visual OSINT: Port 80/443 closed (Optimization).")
                else:
                    try:
                        t = session.get(Target, target_id)
                        if t:
                            t.scan_progress = "Running Visual OSINT..."
                            session.add(t)
                            session.commit()

                        from yads.modules.visual_osint import VisualOSINT
                        vis = VisualOSINT(db_session=session)
                        logger.info(f"[Worker] Step 5: Running {vis.module_name}...")
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
                        logger.error(f"[Worker] Error in Visual OSINT: {e}")
                        session.rollback()

            # 5b. Run Wayback Scanner (Archive)
            if "wayback_scanner" in scan_types:
                try:
                    t = session.get(Target, target_id)
                    if t:
                        t.scan_progress = "Checking Wayback Machine..."
                        session.add(t)
                        session.commit()

                    from yads.modules.wayback_scanner import WaybackScanner
                    wb = WaybackScanner(db_session=session)
                    logger.info(f"[Worker] Step 5b: Running {wb.module_name}...")
                    with LogCapture() as logs:
                        logger.info(f"Starting {wb.module_name} for {domain}")
                        result = wb.process(target_id, domain)
                        captured_logs = logs.get_logs()
                    
                    if result and hasattr(result, 'log_content'):
                         result.log_content = captured_logs
                         session.add(result)
                         session.commit()
                         print(f"[Worker] {wb.module_name} found changes/new data.")
                except Exception as e:
                    logger.error(f"[Worker] Error in Wayback Scanner: {e}")
                    session.rollback()
        
            # 6. Run SSL Scanner
            if "ssl_scanner" in scan_types:
                if not has_https: # Strict check for SSL
                    # Optimization: if port 443 closed, likely no SSL to scan.
                    # NOTE: Some SSL might be on 8443, etc. but scanner currently defaults to 443.
                    logger.info("[Worker] Skipping SSL Scanner: Port 443 closed (Optimization).")
                else:
                    try:
                        t = session.get(Target, target_id)
                        if t:
                            t.scan_progress = "Running SSL Scanner..."
                            session.add(t)
                            session.commit()

                        from yads.modules.ssl_scanner import SSLScanner
                        ssl_mod = SSLScanner(db_session=session)
                        logger.info(f"[Worker] Step 6: Running {ssl_mod.module_name}...")
                        with LogCapture() as logs:
                            logger.info(f"Starting {ssl_mod.module_name} for {domain}")
                            result = ssl_mod.process(target_id, domain)
                            captured_logs = logs.get_logs()
                        
                        if result and hasattr(result, 'log_content'):
                             result.log_content = captured_logs
                             session.add(result)
                             
                             # Check for extracted domains from SSL Certificates
                             if result.data and "extracted_domains" in result.data:
                                 extracted = result.data["extracted_domains"]
                                 new_found = 0
                                 import dns.resolver
                                 
                                 for edomain in extracted:
                                     edomain = edomain.strip().lower()
                                     if not edomain: continue
                                     
                                     # Verify DNS first (Active Check)
                                     # We only add if it resolves, per user preference
                                     resolves = False
                                     try:
                                         dns.resolver.resolve(edomain, 'A')
                                         resolves = True
                                     except:
                                         try:
                                             dns.resolver.resolve(edomain, 'AAAA')
                                             resolves = True
                                         except:
                                             resolves = False
                                     
                                     if resolves:
                                         # Check DB existence
                                         existing_t = session.exec(select(Target).where(Target.domain == edomain)).first()
                                         if not existing_t:
                                             new_target = Target(domain=edomain)
                                             session.add(new_target)
                                             session.commit() # Commit to get ID
                                             session.refresh(new_target)
                                             new_found += 1
                                             print(f"[Worker] Discovered and added new target from SSL: {edomain}")
                                 
                                 if new_found > 0:
                                     print(f"[Worker] SSL Discovery added {new_found} new targets.")

                             session.commit()
                             print(f"[Worker] {ssl_mod.module_name} found changes/new data.")
                        else:
                             print(f"[Worker] {ssl_mod.module_name} no change.")
                    except Exception as e:
                        logger.error(f"[Worker] Error in SSL Scanner: {e}")
                        session.rollback()

            # 7. Run Slow Crawler
            if "crawler" in scan_types:
                if not has_http and not has_https:
                    logger.info("[Worker] Skipping Crawler: Port 80/443 closed (Optimization).")
                else:
                    try:
                        t = session.get(Target, target_id)
                        if t:
                            t.scan_progress = "Running Site Crawler..."
                            session.add(t)
                            session.commit()

                        from yads.modules.crawler import Crawler
                        crawl = Crawler(db_session=session)
                        logger.info(f"[Worker] Step 7: Running {crawl.module_name}...")
                        with LogCapture() as logs:
                            logger.info(f"Starting {crawl.module_name} for {domain}")
                            result = crawl.process(target_id, domain)
                            captured_logs = logs.get_logs()
                        
                        if result and hasattr(result, 'log_content'):
                             result.log_content = captured_logs
                             session.add(result)
                             session.commit()
                             print(f"[Worker] {crawl.module_name} found changes/new data.")
                    except Exception as e:
                        logger.error(f"[Worker] Error in Crawler: {e}")
                        session.rollback()

            # 8. Run Wayback Scanner
            if "wayback_scanner" in scan_types:
                try:
                    t = session.get(Target, target_id)
                    if t:
                        t.scan_progress = "Running Wayback Machine..."
                        session.add(t)
                        session.commit()

                    from yads.modules.wayback_scanner import WaybackScanner
                    wb_scan = WaybackScanner(db_session=session)
                    logger.info(f"[Worker] Step 8: Running {wb_scan.module_name}...")
                    with LogCapture() as logs:
                        logger.info(f"Starting {wb_scan.module_name} for {domain}")
                        result = wb_scan.process(target_id, domain)
                        captured_logs = logs.get_logs()
                    
                    if result: 
                        # Note: process() now returns result even if unchanged, so we can save logs
                        if isinstance(result, object) and hasattr(result, 'log_content'):
                             result.log_content = captured_logs
                             session.add(result)
                             session.commit()
                        print(f"[Worker] {wb_scan.module_name} finished.")
                except Exception as e:
                    logger.error(f"[Worker] Error in Wayback Scanner: {e}")
                    session.rollback()

            # 9. Run Content Discovery (Fuzzing)
            if "content_discovery" in scan_types:
                if not (has_http or has_https):
                    logger.info("[Worker] Skipping Content Discovery: Port 80/443 closed.")
                else:
                    try:
                        t = session.get(Target, target_id)
                        if t:
                            t.scan_progress = "Running Content Discovery (Fuzzing)..."
                            session.add(t)
                            session.commit()

                        from yads.modules.content_discovery import ContentDiscoveryScanner
                        cd_scan = ContentDiscoveryScanner(db_session=session)
                        logger.info(f"[Worker] Step 9: Running {cd_scan.module_name}...")
                        with LogCapture() as logs:
                            logger.info(f"Starting {cd_scan.module_name} for {domain}")
                            result = cd_scan.process(target_id, domain)
                            captured_logs = logs.get_logs()
                        
                        if result and hasattr(result, 'log_content'):
                            result.log_content = captured_logs
                            session.add(result)
                            session.commit()
                            print(f"[Worker] {cd_scan.module_name} found changes/new data.")
                        else:
                            print(f"[Worker] {cd_scan.module_name} no change.")
                    except Exception as e:
                        logger.error(f"[Worker] Error in Content Discovery: {e}")
                        session.rollback()

            # 10. Run TLD Scanner
            if "tld_scanner" in scan_types:
                try:
                    t = session.get(Target, target_id)
                    if t:
                        t.scan_progress = "Running TLD Scanner..."
                        session.add(t)
                        session.commit()

                    from yads.modules.tld_scanner import TLDScanner
                    tld_scan = TLDScanner(db_session=session)
                    logger.info(f"[Worker] Step 10: Running {tld_scan.module_name}...")
                    with LogCapture() as logs:
                        logger.info(f"Starting {tld_scan.module_name} for {domain}")
                        result = tld_scan.process(target_id, domain)
                        captured_logs = logs.get_logs()
                    
                    if result and hasattr(result, 'log_content'):
                        result.log_content = captured_logs
                        session.add(result)
                        session.commit()
                        print(f"[Worker] {tld_scan.module_name} finished.")
                    else:
                        print(f"[Worker] {tld_scan.module_name} finished.")

                except Exception as e:
                    logger.error(f"[Worker] Error in TLD Scanner: {e}")
                    session.rollback()

            # Subdomain Discovery & Auto-Queue Logic
            # Updated to check 'subdomain_scanner' result as the primary source of subdomains
            
            auto_queue_enabled = settings.AUTO_QUEUE_SUBDOMAINS
            try:
                from yads.models import SystemConfig
                aq_conf = session.get(SystemConfig, "AUTO_QUEUE_SUBDOMAINS")
                if aq_conf:
                    auto_queue_enabled = aq_conf.value.lower() == 'true'
            except Exception:
                pass

            try:
                 # Check for Subdomain Scanner results first
                 from yads.models import ScanResult
                 
                 # Prioritize 'subdomain_scanner' if present
                 sub_res = session.exec(select(ScanResult).where(
                     ScanResult.target_id == target_id,
                     ScanResult.module_name == "subdomain_scanner"
                 ).order_by(ScanResult.scanned_at.desc())).first()
                 
                 # Fallback to legacy 'dns_scanner' if subdomain_scanner didn't run effectively
                 if not sub_res:
                     sub_res = session.exec(select(ScanResult).where(
                         ScanResult.target_id == target_id,
                         ScanResult.module_name == "dns_scanner"
                     ).order_by(ScanResult.scanned_at.desc())).first()

                 if sub_res and sub_res.data and "subdomains" in sub_res.data:
                     subs = sub_res.data["subdomains"]
                     
                     new_targets_count = 0
                     queued_count = 0
                     
                     for entry in subs:
                         sub_domain = entry.get("subdomain")
                         if sub_domain and sub_domain != domain: # Avoid self-loop
                             
                             resolves = True
                             
                             # Check existence
                             existing = session.exec(select(Target).where(Target.domain == sub_domain)).first()
                             if not existing:
                                 # Create New Target (Always)
                                 new_target = Target(domain=sub_domain)
                                 session.add(new_target)
                                 session.commit()
                                 session.refresh(new_target)
                                 new_targets_count += 1
                                 
                                 # Queue Scan (Conditional)
                                 if auto_queue_enabled:
                                     celery_app.send_task("yads.worker.run_all_scans", args=[new_target.id, new_target.domain])
                                     queued_count += 1
                                     logger.info(f"[Worker] Auto-queued new subdomain: {sub_domain}")
                                 else:
                                     logger.info(f"[Worker] Discovered new subdomain: {sub_domain} (Auto-queue disabled)")
                     
                     if new_targets_count > 0:
                         logger.info(f"[Worker] Subdomain Discovery: Added {new_targets_count} new targets. Queued: {queued_count}.")

            except Exception as e:
                logger.error(f"[Worker] Error in Subdomain Discovery logic: {e}")
                session.rollback()

            # Reset status
            try:
                 t = session.get(Target, target_id)
                 if t:
                     t.scan_status = "idle"
                     t.scan_progress = f"Last scan completed at {datetime.utcnow().strftime('%H:%M:%S')}"
                     session.add(t)
                     session.commit()
            except Exception as e:
                 logger.error(f"[Worker] Failed to update finish status: {e}")
                 session.rollback()

        logger.info(f"[Worker] Finished scan for {domain}")
    
    finally:
        # Cleanup Handler
        if 'root_logger' in locals() and 'redis_handler' in locals():
            root_logger.removeHandler(redis_handler)
