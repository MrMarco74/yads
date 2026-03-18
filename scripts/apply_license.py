
import os
import sys

# Add project root to sys.path so yads is importable when called with a full path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlmodel import Session, select
from yads.database import engine, wait_for_db
from yads.models import SystemConfig
from yads.core.logging_config import configure_logging

logger = configure_logging("apply_license")

def apply_license():
    license_key = os.getenv("LICENSE_KEY")
    if not license_key:
        logger.info("No LICENSE_KEY environment variable found. Skipping license auto-configuration.")
        return

    logger.info("Found LICENSE_KEY in environment. Applying to SystemConfig...")
    
    # Wait for DB to be potentially ready (especially useful on first boot)
    if not wait_for_db():
        logger.error("Database connection failed. Exiting.")
        sys.exit(1)

    try:
        with Session(engine) as session:
            # Check existing
            config = session.get(SystemConfig, "license_key")
            if config:
                if config.value == license_key:
                    logger.info("License key already match. No change.")
                    return
                else:
                    logger.info("Updating existing license key.")
                    config.value = license_key
            else:
                logger.info("Creating new license key configuration.")
                config = SystemConfig(key="license_key", value=license_key)
            
            session.add(config)
            session.commit()
            logger.info("License key applied successfully.")
            
    except Exception as e:
        logger.error(f"Failed to apply license key: {e}")
        sys.exit(1)

if __name__ == "__main__":
    apply_license()
