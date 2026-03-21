import logging
from datetime import datetime, timedelta, timezone
from sqlmodel import Session, delete
from yads.database import engine
from yads.models import ScanResult, HTTPTraffic, SecurityAuditLog, SystemAlertLog
from yads.config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("yads.cleanup")

def run_cleanup():
    """
    Deletes old records from the database based on retention settings in config.py.
    This fulfills DSGVO (data minimization) and DORA/NIS2 (retention) requirements.
    """
    now = datetime.now(timezone.utc)
    logger.info(f"Starting data retention cleanup at {now}")
    
    with Session(engine) as session:
        try:
            # 1. Scan Results (Default: 5 years / 1825 days)
            # DORA Art. 12 requires 5 years for ICT-related events.
            retention_cutoff = now - timedelta(days=settings.DATA_RETENTION_DAYS)
            statement = delete(ScanResult).where(ScanResult.scanned_at < retention_cutoff)
            result = session.exec(statement)
            logger.info(f"Deleted {result.rowcount} old ScanResults (older than {settings.DATA_RETENTION_DAYS} days)")
            
            # 2. HTTP Traffic Logs (Default: 30 days)
            # DSGVO requires short retention for potentially PII-containing logs.
            log_cutoff = now - timedelta(days=settings.LOG_RETENTION_DAYS)
            statement = delete(HTTPTraffic).where(HTTPTraffic.timestamp < log_cutoff)
            result = session.exec(statement)
            logger.info(f"Deleted {result.rowcount} old HTTPTraffic logs (older than {settings.LOG_RETENTION_DAYS} days)")
            
            # 3. Security Audit Logs (Default: 5 years / 1825 days)
            # Hash-chained logs for compliance auditing.
            audit_cutoff = now - timedelta(days=1825) 
            statement = delete(SecurityAuditLog).where(SecurityAuditLog.timestamp < audit_cutoff)
            result = session.exec(statement)
            logger.info(f"Deleted {result.rowcount} old SecurityAuditLogs (older than 1825 days)")

            # 4. System Health Alerts (Default: 30 days)
            # Reusing log_cutoff for consistency.
            statement = delete(SystemAlertLog).where(SystemAlertLog.fired_at < log_cutoff)
            result = session.exec(statement)
            logger.info(f"Deleted {result.rowcount} old SystemAlertLogs (older than {settings.LOG_RETENTION_DAYS} days)")
            
            session.commit()
            logger.info("Cleanup completed successfully.")
        except Exception as e:
            session.rollback()
            logger.error(f"Cleanup failed: {e}")
            raise

if __name__ == "__main__":
    run_cleanup()
