import os
from pydantic_settings import BaseSettings

from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "YADS - Yet Another DNS Scanner"
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/yads_db")
    
    # Redis / Celery
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    # Scanner Configs
    CHROME_BIN: str = os.getenv("CHROME_BIN", "/usr/bin/google-chrome")
    AUTO_QUEUE_SUBDOMAINS: bool = False
    SCAN_QUEUE_RATE_LIMIT: Optional[str] = None  # No default rate limit
    WEB_REQUEST_TIMEOUT: int = int(os.getenv("YADS_WEB_TIMEOUT", 10))
    
    class Config:
        env_file = ".env"

settings = Settings()
