import os
import sys
import logging
from sqlmodel import Session, create_engine, select

# Add project root to path
sys.path.append(os.getcwd())

from yads.config import settings
from yads.modules.crawler import Crawler
from yads.modules.visual_osint import VisualOSINT
from yads.models import Target

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("verify_sc")

def verify():
    engine = create_engine(settings.DATABASE_URL)
    with Session(engine) as session:
        # Pick a target that likely has a web server
        # In a real environment, we'd use a known test domain.
        # Here we just try to find one or fail gracefully.
        target = session.exec(select(Target)).first()
        if not target:
            logger.error("No targets found in DB. Please add a target first.")
            return

        domain = target.domain
        logger.info(f"Targeting: {domain}")

        # 1. Test Crawler
        logger.info("--- Testing Crawler ---")
        crawler = Crawler(db_session=session)
        # Force a small crawl
        crawler_result = crawler.run_scan(domain)
        
        screenshots = [node.get('screenshot') for node in crawler_result.get('nodes', []) if node.get('screenshot')]
        logger.info(f"Crawler finished. Pages: {crawler_result.get('stats', {}).get('pages_crawled')}")
        logger.info(f"Screenshots captured: {len(screenshots)}")
        for sc in screenshots:
            path = f"yads/api/static/screenshots/{sc}"
            if os.path.exists(path):
                logger.info(f"Verified screenshot exists: {path}")
            else:
                logger.error(f"Screenshot missing: {path}")

        # 2. Test VisualOSINT
        logger.info("--- Testing VisualOSINT ---")
        vis = VisualOSINT(db_session=session)
        # vis.process creates a ScanResult
        result = vis.process(target.id, domain)
        
        if result and result.data.get('screenshot_path'):
            sc_path = f"yads/api/static/screenshots/{result.data['screenshot_path']}"
            if os.path.exists(sc_path):
                logger.info(f"Verified VisualOSINT screenshot exists: {sc_path}")
            else:
                logger.error(f"VisualOSINT screenshot missing: {sc_path}")
        else:
            logger.warning("VisualOSINT did not produce a screenshot (check logs).")

if __name__ == "__main__":
    verify()
