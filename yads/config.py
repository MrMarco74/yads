import os
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource
from typing import Optional
from pydantic import model_validator
from urllib.parse import quote
import re

class Settings(BaseSettings):
    PROJECT_NAME: str = "YADS"
    VERSION: str = "1.47.2"
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://yads:yads_dev_local@db:5432/yads")
    POSTGRES_PASSWORD: Optional[str] = None
    POSTGRES_USER: Optional[str] = None
    POSTGRES_DB: Optional[str] = None
    
    # Redis / Celery
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://redis:6379/0")
    
    # Scanner Configs
    CHROME_BIN: str = os.getenv("CHROME_BIN", "/usr/bin/google-chrome")
    AUTO_QUEUE_SUBDOMAINS: bool = False
    SCAN_QUEUE_RATE_LIMIT: Optional[str] = None
    WEB_REQUEST_TIMEOUT: int = int(os.getenv("YADS_WEB_TIMEOUT", 7))
    QUEUE_PAUSE_ON_BOOT: bool = os.getenv("QUEUE_PAUSE_ON_BOOT", "false").lower() == "true"

    # Authentication & Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "changeme_in_production_please_super_secret")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    MFA_ENABLED: bool = os.getenv("MFA_ENABLED", "true").lower() == "true"
    
    # Paths
    BASE_DIR: str = os.path.dirname(os.path.abspath(__file__))
    STATIC_DIR: str = os.path.join(BASE_DIR, "api", "static")

    # TLS/SSL Certificate Settings
    # Environment variable override to disable HTTPS_ONLY setting (emergency fallback)
    DISABLE_HTTPS_ONLY: bool = os.getenv("DISABLE_HTTPS_ONLY", "false").lower() == "true"

    # Custom CA certificate bundle path (for internal PKI)
    CUSTOM_CA_CERT_PATH: Optional[str] = os.getenv("CUSTOM_CA_CERT_PATH", None)

    # Client certificate for mTLS authentication
    CLIENT_CERT_PATH: Optional[str] = os.getenv("CLIENT_CERT_PATH", None)
    CLIENT_KEY_PATH: Optional[str] = os.getenv("CLIENT_KEY_PATH", None)

    # Licensing
    LICENSE_PUBLIC_KEY: str = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQURXL0UxMzJWUzkwQlZLclZTYW9zYzVablRIZERQME1WRGhPaDZZNTYwVG89Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo="
    LICENSE_KEY: Optional[str] = None

    # Bug Report / Support Portal
    SUPPORT_PORTAL_URL: str = os.getenv("SUPPORT_PORTAL_URL", "https://support.yads-security.com")
    # X25519 public key (base64 raw, 32 bytes) — generated via scripts/generate_support_keypair.py
    SUPPORT_DEV_PUBLIC_KEY: str = "0Q7SCbynTF/x9jd0E6VXbHfdDliZZsCTii7Inyfekj8="
    # Set to false to skip TLS verification for the support portal (dev/staging without proper cert)
    SUPPORT_PORTAL_VERIFY_SSL: bool = os.getenv("SUPPORT_PORTAL_VERIFY_SSL", "true").lower() == "true"

    # Custom Module Signing
    # All custom module uploads require a valid Ed25519 signature by default.
    # To disable signature enforcement (e.g. in dev environments without a keypair),
    # set MODULE_SIGNING_DISABLED=true explicitly.
    # Generate a keypair with: python scripts/sign_module.py --keygen
    MODULE_SIGNING_PUBLIC_KEY: Optional[str] = None
    MODULE_SIGNING_DISABLED: bool = False

    # Setup Wizard
    SETUP_COMPLETE: bool = False
    SETUP_TOKEN: Optional[str] = None
    CONFIG_PATH: str = os.getenv("CONFIG_PATH", "/app/data/config.env")

    # Phase 4 Threat Intelligence API Keys
    ABUSEIPDB_API_KEY: Optional[str] = None
    OTX_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    CENSYS_API_ID: Optional[str] = None
    CENSYS_API_SECRET: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None

    # Auth Mode
    AUTH_MODE: str = os.getenv("AUTH_MODE", "local")  # "local" oder "oidc"

    # OIDC/Keycloak Settings (nur relevant wenn AUTH_MODE=oidc)
    # OIDC_SERVER_URL:        intern (Docker-zu-Docker, Token-Exchange server-seitig)
    # OIDC_PUBLIC_URL:        extern (Browser-Redirect zu Keycloak Login-Seite)
    # Lokal: OIDC_SERVER_URL=http://keycloak:8080, OIDC_PUBLIC_URL=http://localhost:8080
    OIDC_SERVER_URL: str = os.getenv("OIDC_SERVER_URL", "http://keycloak:8080")
    OIDC_PUBLIC_URL: str = os.getenv("OIDC_PUBLIC_URL", "http://localhost:8080")
    OIDC_REALM: str = os.getenv("OIDC_REALM", "frischkorn")
    OIDC_CLIENT_ID: str = os.getenv("OIDC_CLIENT_ID", "yads")
    OIDC_CLIENT_SECRET: str = os.getenv("OIDC_CLIENT_SECRET", "frischkorn-yads-secret")
    OIDC_REDIRECT_URI: str = os.getenv("OIDC_REDIRECT_URI", "http://localhost:8085/auth/oidc/callback")

    # Prometheus Metrics
    METRICS_ENABLED: bool = os.getenv("METRICS_ENABLED", "false").lower() == "true"
    METRICS_AUTH_MODE: str = os.getenv("METRICS_AUTH_MODE", "token")  # none, token, user
    METRICS_TOKEN: Optional[str] = os.getenv("METRICS_TOKEN", None)
    METRICS_INCLUDE_TENANT_LABELS: bool = os.getenv("METRICS_INCLUDE_TENANT_LABELS", "false").lower() == "true"
    METRICS_POLL_INTERVAL: int = int(os.getenv("METRICS_POLL_INTERVAL", "30"))

    class Config:
        env_file = os.getenv("CONFIG_PATH", "/app/data/config.env")
        env_file_encoding = 'utf-8'
        extra = "ignore"

    @model_validator(mode='after')
    def fix_masked_password(self):
        if self.DATABASE_URL and "***" in self.DATABASE_URL and self.POSTGRES_PASSWORD:
            # URL-encode the password so special chars like @ don't break URL parsing
            encoded = quote(self.POSTGRES_PASSWORD, safe='')
            self.DATABASE_URL = self.DATABASE_URL.replace("***", encoded)
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
