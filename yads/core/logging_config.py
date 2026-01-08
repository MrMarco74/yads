import logging
import os
import sys
from logging.handlers import RotatingFileHandler

def configure_logging(service_name: str):
    """
    Configures logging to write to console and a shared file.
    """
    log_dir = os.getenv("LOG_DIR", "logs")
    os.makedirs(log_dir, exist_ok=True)
    # Use service name for distinct log files to avoid locking issues
    log_file = os.path.join(log_dir, f"{service_name}.log")

    # formatter = logging.Formatter(
    #     "%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    #     datefmt="%Y-%m-%d %H:%M:%S"
    # )
    
    # JSON-like format for easier parsing if needed, or just clean text
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)-15s | %(message)s"
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File Handler (Shared)
    file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    # Set specific loggers
    logging.getLogger("uvicorn.access").handlers = root_logger.handlers
    logging.getLogger("uvicorn.error").handlers = root_logger.handlers
    
    logger = logging.getLogger(service_name)
    logger.info(f"Logging initialized for {service_name}")
    return logger
