import os
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource
from typing import Optional
from pydantic import model_validator
from urllib.parse import quote
import re

class Settings(BaseSettings):
    PROJECT_NAME: str = "YADS"
    VERSION: str = "2.6.5"
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    CORS_ALLOWED_ORIGINS: list[str] = os.getenv("CORS_ALLOWED_ORIGINS", "*").split(",")

    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://yads:***@db:5432/yads")
    POSTGRES_PASSWORD: Optional[str] = None
    POSTGRES_USER: Optional[str] = None
    POSTGRES_DB: Optional[str] = None
    
    # Redis / Celery
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://redis:6379/0")
    # Celery broker URL — defaults to RabbitMQ; falls back to REDIS_URL if not set
    BROKER_URL: str = os.getenv("BROKER_URL", "amqp://yads:***@rabbitmq:5672//")
    
    # Scanner Configs
    AUTO_QUEUE_SUBDOMAINS: bool = False
    SCAN_QUEUE_RATE_LIMIT: Optional[str] = None
    WEB_REQUEST_TIMEOUT: int = int(os.getenv("YADS_WEB_TIMEOUT", 7))
    QUEUE_PAUSE_ON_BOOT: bool = os.getenv("QUEUE_PAUSE_ON_BOOT", "false").lower() == "true"

    # Authentication & Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "changeme_in_production_please_super_secret")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    MFA_ENABLED: bool = os.getenv("MFA_ENABLED", "true").lower() == "true"
    YADS_ENCRYPTION_KEY: Optional[str] = os.getenv("YADS_ENCRYPTION_KEY", None)
    
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

    # Custom Module Signing
    # All custom module uploads require a valid Ed25519 signature by default.
    # To disable signature enforcement (e.g. in dev environments without a keypair),
    # set MODULE_SIGNING_DISABLED=true explicitly.
    # Generate a keypair with: python scripts/sign_module.py --keygen
    MODULE_SIGNING_PUBLIC_KEY: Optional[str] = None
    MODULE_SIGNING_DISABLED: bool = False
    # Path to the Ed25519 private key PEM file used for auto-signing uploaded modules.
    # When set, the Plugin Manager signs every uploaded ZIP automatically — no external
    # signing tool needed. Only set this on trusted internal instances.
    # Example: MODULE_SIGNING_PRIVATE_KEY_PATH=/run/secrets/yads_module_signing.key
    MODULE_SIGNING_PRIVATE_KEY_PATH: Optional[str] = None

    # Setup
    SETUP_COMPLETE: bool = False
    CONFIG_PATH: str = os.getenv("CONFIG_PATH", "/app/data/config.env")
    
    # Retention / Lifecycle
    DATA_RETENTION_DAYS: int = int(os.getenv("DATA_RETENTION_DAYS", 1825))  # 5 years (DORA)
    LOG_RETENTION_DAYS: int = int(os.getenv("LOG_RETENTION_DAYS", 30))      # 30 days (DSGVO)
    SUPPORT_IP_RETENTION_DAYS: int = int(os.getenv("SUPPORT_IP_RETENTION_DAYS", 7)) # 7 days

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
    OIDC_CLIENT_SECRET: str = os.getenv("OIDC_CLIENT_SECRET", "***")
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
    def assemble_database_url(self):
        # Case 1: Individual components are provided (most robust)
        # We check for POSTGRES_PASSWORD and either SERVER or DB_URL with placeholder
        if self.POSTGRES_PASSWORD:
            user = self.POSTGRES_USER or "yads"
            password = quote(self.POSTGRES_PASSWORD, safe='')
            db = self.POSTGRES_DB or "yads"
            # Extract host/port from current URL if it looks like a placeholder or default
            # Default: postgresql://yads:yads_dev_local@db:5432/yads
            from sqlalchemy.engine.url import make_url
            try:
                url_obj = make_url(self.DATABASE_URL)
                host = url_obj.host or "db"
                port = url_obj.port or 5432
                
                # Rebuild safely
                self.DATABASE_URL = f"postgresql://{user}:{password}@{host}:{port}/{db}"
            except Exception:
                # Fallback to simple replace if URL parsing fails
                if "***" in self.DATABASE_URL:
                    self.DATABASE_URL = self.DATABASE_URL.replace("***", password)
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

import warnings as _warnings

_DEFAULT_SECRET = "changeme_in_production_please_super_secret"
if settings.SECRET_KEY == _DEFAULT_SECRET:
    _warnings.warn(
        "SECURITY: SECRET_KEY is set to the default value. "
        "All JWT tokens can be forged. Set SECRET_KEY to a random value in production!",
        stacklevel=2,
    )

_DEFAULT_OIDC_SECRET = "frischkorn-yads-secret"
if settings.AUTH_MODE == "oidc" and settings.OIDC_CLIENT_SECRET == _DEFAULT_OIDC_SECRET:
    _warnings.warn(
        "SECURITY: OIDC_CLIENT_SECRET is set to the default value. "
        "Set OIDC_CLIENT_SECRET to the actual client secret from your IdP in production!",
        stacklevel=2,
    )
