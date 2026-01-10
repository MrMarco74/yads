from sqlmodel import select, Session
from yads.models import SystemConfig
import logging

logger = logging.getLogger(__name__)

class StopSignalError(Exception):
    """Raised when the global stop signal is detected."""
    pass

def check_stop_signal(session: Session):
    """
    Checks if QUEUE_ACTIVE is false in SystemConfig.
    If so, raises StopSignalError.
    """
    try:
        conf = session.exec(select(SystemConfig).where(SystemConfig.key == "QUEUE_ACTIVE")).first()
        if conf and conf.value == "false":
            logger.warning("STOP SIGNAL DETECTED: Aborting operation.")
            raise StopSignalError("Global Stop Signal Detected")
    except Exception as e:
        # Don't let DB errors crash the scan, unless it's the StopSignal
        if isinstance(e, StopSignalError):
            raise e
        logger.warning(f"Failed to check stop signal: {e}")
