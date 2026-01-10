from sqlmodel import Session, select, create_engine, func, text
from yads.models import ScanResult, Target
from yads.config import settings
import logging
import datetime
import json

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("consolidate")

engine = create_engine(settings.DATABASE_URL)

MODULES_TO_FIX = ["web_analyzer", "infrastructure_scanner", "ssl_scanner", "tld_scanner"]

def score_data(module_name: str, data: dict) -> int:
    """
    Returns a 'quality score' for the data to decide which is better.
    """
    if not data: return 0
    score = 0
    
    if module_name == "web_analyzer":
        # More technologies = better
        score += len(data.get("tech_stack", [])) * 10
        # Valid HTTP Status = better
        if data.get("http_status", 0) > 0: score += 5
        # Title found = better
        if data.get("title"): score += 5
        # Screenshot exists = better
        if data.get("screenshot_path"): score += 5
    
    elif module_name == "infrastructure_scanner":
        # GeoIP exists = better
        if data.get("geoip"): score += 20
        # Cloud Provider exists = better
        if data.get("cloud_provider"): score += 10
        # IP exists = better
        if data.get("ip"): score += 5

    elif module_name == "ssl_scanner":
        # Cert info exists
        if data.get("subject_common_name"): score += 10
        if data.get("issuer_common_name"): score += 5

    return score

def consolidate():
    logger.info("Starting Data Consolidation Run...")
    
    with Session(engine) as session:
        targets = session.exec(select(Target)).all()
        logger.info(f"Processing {len(targets)} targets...")
        
        restored_count = 0
        
        for t in targets:
            for mod in MODULES_TO_FIX:
                # Get ALL results for this target/module
                history = session.exec(select(ScanResult).where(
                    ScanResult.target_id == t.id,
                    ScanResult.module_name == mod
                ).order_by(ScanResult.scanned_at.desc())).all()
                
                if not history:
                    continue
                
                latest = history[0]
                latest_score = score_data(mod, latest.data)
                
                # Find best in history
                best_res = None
                best_score = -1
                
                for res in history:
                    s = score_data(mod, res.data)
                    if s > best_score:
                        best_score = s
                        best_res = res
                
                # Logic: If Best is significantly better than Latest, Restore it.
                # "Significantly" avoids trashing mostly-ok latest data with old data just for +1 point.
                # But for "Empty" vs "Full", the score diff is huge.
                
                # Special Case: If latest is effectively "Empty/Failed" (score < 5) and best is good.
                if latest_score < 5 and best_score > 10:
                    logger.info(f"[{t.domain}][{mod}] Latest Score: {latest_score}, Best Score: {best_score}. RESTORING.")
                    
                    # Create new result copying Best Data
                    restored = ScanResult(
                        target_id=t.id,
                        module_name=mod,
                        scanned_at=datetime.datetime.utcnow(),
                        result_hash=best_res.result_hash,
                        data=best_res.data,
                        log_content=f"Restored from historical aggregate (Original: {best_res.scanned_at})"
                    )
                    session.add(restored)
                    restored_count += 1
        
        session.commit()
        logger.info(f"Consolidation Complete. Restored/Aggregated {restored_count} entries.")

if __name__ == "__main__":
    consolidate()
