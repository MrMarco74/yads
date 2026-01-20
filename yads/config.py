import os
from pydantic_settings import BaseSettings

from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "YADS"
    VERSION: str = "1.11.0"
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/yads_db")
    
    # Redis / Celery
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    # Scanner Configs
    CHROME_BIN: str = os.getenv("CHROME_BIN", "/usr/bin/google-chrome")
    AUTO_QUEUE_SUBDOMAINS: bool = False
    SCAN_QUEUE_RATE_LIMIT: Optional[str] = None  # No default rate limit
    WEB_REQUEST_TIMEOUT: int = int(os.getenv("YADS_WEB_TIMEOUT", 10))

    # Authentication & Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "changeme_in_production_please_super_secret")
    ALGORITHM: str = "HS256"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 # Default to 1 hour, configurable by Admin via SystemConfig later potentially
    MFA_ENABLED: bool = os.getenv("MFA_ENABLED", "true").lower() == "true"
    
    # Paths
    BASE_DIR: str = os.path.dirname(os.path.abspath(__file__))
    STATIC_DIR: str = os.path.join(BASE_DIR, "api", "static")

    # Licensing (Ed25519 Public Key)
    # This key matches the Private Key held by the vendor.
    LICENSE_PUBLIC_KEY: str = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQStucEN2ZWpHSC9xMU9ZN3BHbi9tVmVxUlRqY1ZWZkFHb1hoeWdWdm8yZVU9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo="

    class Config:
        env_file = ".env"

settings = Settings()
