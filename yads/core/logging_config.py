import logging
import os
import sys
from logging.handlers import RotatingFileHandler

import urllib3

def configure_logging(service_name: str):
    """
    Configures logging to write to console and a shared file.
    """
    # Recon/scanner modules intentionally use verify=False (targets are
    # arbitrary external hosts, often with self-signed/expired/misconfigured
    # certs -- that's exactly what's being scanned for). Only a handful of
    # modules called urllib3.disable_warnings() individually, so every other
    # verify=False request flooded the logs with a multi-line
    # InsecureRequestWarning per call. Suppress it once, process-wide, here
    # instead of requiring every module to remember to do it locally.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
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

    # File Handler (Shared/Service Specific)
    file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    # Separate Uvicorn Logging (only relevant for API)
    # If we are in API context (usually implied by usage of uvicorn loggers)
    uvicorn_log_file = os.path.join(log_dir, "uvicorn.log")
    uv_file_handler = RotatingFileHandler(uvicorn_log_file, maxBytes=10*1024*1024, backupCount=5)
    uv_file_handler.setFormatter(formatter)
    
    for uv_name in ["uvicorn", "uvicorn.access", "uvicorn.error"]:
        uv_logger = logging.getLogger(uv_name)
        uv_logger.handlers = [] # clear default stream handlers
        uv_logger.addHandler(uv_file_handler)
        uv_logger.propagate = False # Stop from going to root (yads-api.log)

    logger = logging.getLogger(service_name)
    logger.info(f"Logging initialized for {service_name}")
    return logger
