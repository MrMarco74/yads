from sqlmodel import Session, select, create_engine
from yads.models import ScanResult
from yads.config import settings
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("backfill")

engine = create_engine(settings.DATABASE_URL)

def backfill():
    logger.info("Starting Login Detection Backfill...")
    with Session(engine) as session:
        # Get all web_analyzer results
        results = session.exec(select(ScanResult).where(ScanResult.module_name == "web_analyzer")).all()
        
        count = 0
        for res in results:
            data = res.data
            is_login = False
            
            # Check 1: 401
            if data.get("status_code") == 401 or data.get("http_status") == 401:
                is_login = True
                
            # Check 2: Title
            title = data.get("title", "").lower() if data.get("title") else ""
            if "login" in title or "sign in" in title or "anmeldung" in title:
                is_login = True
                
            # Check 3: Keywords (if recorded)
            keywords = [k.lower() for k in data.get("keywords_found", [])]
            if "login" in keywords: # "dashboard" is too generic maybe?
                is_login = True
                
            # Update only if not already set or if we found it match
            if is_login and not data.get("is_login_page"):
                res.data["is_login_page"] = True
                session.add(res)
                count += 1
                logger.info(f"Marked as Login: {title} (ID: {res.id})")
            elif not data.get("is_login_page"):
                # Initialize explicitly to False if missing
                res.data["is_login_page"] = False
                session.add(res)
                
        session.commit()
        logger.info(f"Backfill Complete. Updated {count} results.")

if __name__ == "__main__":
    backfill()
