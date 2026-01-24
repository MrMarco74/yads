import os
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource
from typing import Optional
from pydantic import model_validator
import re

class Settings(BaseSettings):
    PROJECT_NAME: str = "YADS"
    VERSION: str = "1.13.4"
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://yads:changeme@db:5432/yads")
    POSTGRES_PASSWORD: Optional[str] = None
    POSTGRES_USER: Optional[str] = None
    POSTGRES_DB: Optional[str] = None
    
    # Redis / Celery
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://redis:6379/0")
    
    # Scanner Configs
    CHROME_BIN: str = os.getenv("CHROME_BIN", "/usr/bin/google-chrome")
    AUTO_QUEUE_SUBDOMAINS: bool = False
    SCAN_QUEUE_RATE_LIMIT: Optional[str] = None
    WEB_REQUEST_TIMEOUT: int = int(os.getenv("YADS_WEB_TIMEOUT", 10))

    # Authentication & Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "changeme_in_production_please_super_secret")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    MFA_ENABLED: bool = os.getenv("MFA_ENABLED", "true").lower() == "true"
    
    # Paths
    BASE_DIR: str = os.path.dirname(os.path.abspath(__file__))
    STATIC_DIR: str = os.path.join(BASE_DIR, "api", "static")

    # Licensing
    LICENSE_PUBLIC_KEY: str = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQTFJZ2pBSUx6elI2cHNsSFpidHJER1BHUlcxclNhSDVhLyszM2dEdWVNdVU9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo="
    LICENSE_KEY: Optional[str] = None

    # Setup Wizard
    SETUP_COMPLETE: bool = False
    CONFIG_PATH: str = os.getenv("CONFIG_PATH", "/app/data/config.env")

    class Config:
        env_file = os.getenv("CONFIG_PATH", "/app/data/config.env")
        env_file_encoding = 'utf-8'
        extra = "ignore"

    @model_validator(mode='after')
    def fix_masked_password(self):
        if self.DATABASE_URL and "***" in self.DATABASE_URL and self.POSTGRES_PASSWORD:
            new_url = self.DATABASE_URL.replace("***", self.POSTGRES_PASSWORD)
            self.DATABASE_URL = new_url
        return self

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return init_settings, dotenv_settings, env_settings, file_secret_settings

settings = Settings()
