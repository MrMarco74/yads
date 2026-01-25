"""
TLS/SSL Certificate Configuration
=================================
Provides centralized TLS configuration for scanning internal infrastructure
behind corporate PKI (custom CA certificates and client certificates).

Features:
- Custom CA certificate support for internal PKI
- Client certificate (mTLS) authentication
- HTTPS-only enforcement with environment variable override
- Certificate validation and loading

Configuration Sources (in priority order):
1. Environment variables (highest priority, emergency override)
2. SystemConfig database settings
3. Default values (lowest priority)

Environment Variables:
- DISABLE_HTTPS_ONLY: Set to "true" to disable HTTPS-only enforcement
- CUSTOM_CA_CERT_PATH: Path to custom CA certificate bundle
- CLIENT_CERT_PATH: Path to client certificate (PEM format)
- CLIENT_KEY_PATH: Path to client private key (PEM format)
"""

import os
import logging
from typing import Optional, Tuple, Any, Dict
from dataclasses import dataclass

import requests

logger = logging.getLogger("yads.core.tls_config")


@dataclass
class TLSConfig:
    """TLS configuration container."""
    https_only: bool = False
    custom_ca_cert_path: Optional[str] = None
    client_cert_path: Optional[str] = None
    client_key_path: Optional[str] = None
    verify_ssl: bool = True

    def get_verify(self) -> Any:
        """
        Get the 'verify' parameter for requests.

        Returns:
            - Path to CA bundle if custom CA is configured
            - True for system CA verification
            - False if SSL verification is disabled
        """
        if not self.verify_ssl:
            return False

        if self.custom_ca_cert_path and os.path.exists(self.custom_ca_cert_path):
            return self.custom_ca_cert_path

        return True

    def get_cert(self) -> Optional[Tuple[str, str]]:
        """
        Get the 'cert' parameter for requests (client certificate).

        Returns:
            Tuple of (cert_path, key_path) if configured, None otherwise.
        """
        if self.client_cert_path and self.client_key_path:
            if os.path.exists(self.client_cert_path) and os.path.exists(self.client_key_path):
                return (self.client_cert_path, self.client_key_path)

        return None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "https_only": self.https_only,
            "custom_ca_cert_path": self.custom_ca_cert_path,
            "client_cert_path": self.client_cert_path,
            "client_key_path": self.client_key_path,
            "verify_ssl": self.verify_ssl,
        }


class TLSConfigManager:
    """
    Manages TLS configuration with database and environment variable support.

    Priority order:
    1. Environment variable DISABLE_HTTPS_ONLY overrides database HTTPS_ONLY
    2. Database SystemConfig values
    3. Environment variable paths (for certificates)
    4. Default values
    """

    # SystemConfig keys
    KEY_HTTPS_ONLY = "HTTPS_ONLY"
    KEY_CUSTOM_CA_CERT_PATH = "CUSTOM_CA_CERT_PATH"
    KEY_CLIENT_CERT_PATH = "CLIENT_CERT_PATH"
    KEY_CLIENT_KEY_PATH = "CLIENT_KEY_PATH"
    KEY_VERIFY_SSL = "VERIFY_SSL"

    def __init__(self):
        self._cached_config: Optional[TLSConfig] = None

    def get_config(self, db_session=None) -> TLSConfig:
        """
        Get the current TLS configuration.

        Args:
            db_session: Optional SQLModel session for database access.

        Returns:
            TLSConfig instance with current settings.
        """
        from yads.config import settings

        config = TLSConfig()

        # 1. Load from database if session provided
        if db_session:
            config = self._load_from_db(db_session)

        # 2. Apply environment variable overrides
        config = self._apply_env_overrides(config, settings)

        return config

    def _load_from_db(self, db_session) -> TLSConfig:
        """Load TLS configuration from database."""
        from yads.models import SystemConfig

        config = TLSConfig()

        try:
            # HTTPS Only
            https_only_conf = db_session.get(SystemConfig, self.KEY_HTTPS_ONLY)
            if https_only_conf:
                config.https_only = https_only_conf.value.lower() == "true"

            # Custom CA Certificate
            ca_conf = db_session.get(SystemConfig, self.KEY_CUSTOM_CA_CERT_PATH)
            if ca_conf and ca_conf.value:
                config.custom_ca_cert_path = ca_conf.value

            # Client Certificate
            client_cert_conf = db_session.get(SystemConfig, self.KEY_CLIENT_CERT_PATH)
            if client_cert_conf and client_cert_conf.value:
                config.client_cert_path = client_cert_conf.value

            # Client Key
            client_key_conf = db_session.get(SystemConfig, self.KEY_CLIENT_KEY_PATH)
            if client_key_conf and client_key_conf.value:
                config.client_key_path = client_key_conf.value

            # SSL Verification
            verify_conf = db_session.get(SystemConfig, self.KEY_VERIFY_SSL)
            if verify_conf:
                config.verify_ssl = verify_conf.value.lower() != "false"

        except Exception as e:
            logger.warning(f"Failed to load TLS config from database: {e}")

        return config

    def _apply_env_overrides(self, config: TLSConfig, settings) -> TLSConfig:
        """Apply environment variable overrides to configuration."""

        # CRITICAL: Environment variable can DISABLE https_only enforcement
        # This is the emergency fallback for when the system is locked out
        if settings.DISABLE_HTTPS_ONLY:
            logger.warning("HTTPS_ONLY enforcement DISABLED via environment variable")
            config.https_only = False

        # Certificate paths from environment (if not set in DB)
        if settings.CUSTOM_CA_CERT_PATH and not config.custom_ca_cert_path:
            config.custom_ca_cert_path = settings.CUSTOM_CA_CERT_PATH

        if settings.CLIENT_CERT_PATH and not config.client_cert_path:
            config.client_cert_path = settings.CLIENT_CERT_PATH

        if settings.CLIENT_KEY_PATH and not config.client_key_path:
            config.client_key_path = settings.CLIENT_KEY_PATH

        return config

    def save_config(self, db_session, config: TLSConfig) -> bool:
        """
        Save TLS configuration to database.

        Args:
            db_session: SQLModel session.
            config: TLSConfig instance to save.

        Returns:
            True if saved successfully, False otherwise.
        """
        from yads.models import SystemConfig

        try:
            def upsert(key: str, value: str):
                conf = db_session.get(SystemConfig, key)
                if not conf:
                    conf = SystemConfig(key=key, value=value)
                else:
                    conf.value = value
                db_session.add(conf)

            upsert(self.KEY_HTTPS_ONLY, str(config.https_only).lower())

            if config.custom_ca_cert_path:
                upsert(self.KEY_CUSTOM_CA_CERT_PATH, config.custom_ca_cert_path)
            if config.client_cert_path:
                upsert(self.KEY_CLIENT_CERT_PATH, config.client_cert_path)
            if config.client_key_path:
                upsert(self.KEY_CLIENT_KEY_PATH, config.client_key_path)

            upsert(self.KEY_VERIFY_SSL, str(config.verify_ssl).lower())

            db_session.commit()
            logger.info("TLS configuration saved to database")
            return True

        except Exception as e:
            logger.error(f"Failed to save TLS config: {e}")
            db_session.rollback()
            return False

    def validate_certificates(self, config: TLSConfig) -> Dict[str, Any]:
        """
        Validate certificate files exist and are readable.

        Returns:
            Dictionary with validation results.
        """
        results = {
            "valid": True,
            "errors": [],
            "warnings": []
        }

        # Check CA certificate
        if config.custom_ca_cert_path:
            if not os.path.exists(config.custom_ca_cert_path):
                results["valid"] = False
                results["errors"].append(f"CA certificate not found: {config.custom_ca_cert_path}")
            elif not os.access(config.custom_ca_cert_path, os.R_OK):
                results["valid"] = False
                results["errors"].append(f"CA certificate not readable: {config.custom_ca_cert_path}")

        # Check client certificate
        if config.client_cert_path:
            if not os.path.exists(config.client_cert_path):
                results["valid"] = False
                results["errors"].append(f"Client certificate not found: {config.client_cert_path}")
            elif not os.access(config.client_cert_path, os.R_OK):
                results["valid"] = False
                results["errors"].append(f"Client certificate not readable: {config.client_cert_path}")

        # Check client key
        if config.client_key_path:
            if not os.path.exists(config.client_key_path):
                results["valid"] = False
                results["errors"].append(f"Client key not found: {config.client_key_path}")
            elif not os.access(config.client_key_path, os.R_OK):
                results["valid"] = False
                results["errors"].append(f"Client key not readable: {config.client_key_path}")

        # Check for mismatched client cert/key
        if bool(config.client_cert_path) != bool(config.client_key_path):
            results["valid"] = False
            results["errors"].append("Client certificate and key must both be provided")

        return results

    def is_https_required(self, db_session=None) -> bool:
        """
        Check if HTTPS is required for connections.

        This respects the DISABLE_HTTPS_ONLY environment variable.
        """
        from yads.config import settings

        # Environment variable override
        if settings.DISABLE_HTTPS_ONLY:
            return False

        # Check database setting
        if db_session:
            from yads.models import SystemConfig
            try:
                conf = db_session.get(SystemConfig, self.KEY_HTTPS_ONLY)
                if conf:
                    return conf.value.lower() == "true"
            except Exception:
                pass

        return False

    def apply_to_session(self, session: requests.Session, db_session=None) -> requests.Session:
        """
        Apply TLS configuration to a requests Session.

        Args:
            session: requests.Session instance to configure.
            db_session: Optional database session for loading config.

        Returns:
            Configured requests.Session.
        """
        config = self.get_config(db_session)

        # Apply SSL verification
        session.verify = config.get_verify()

        # Apply client certificate
        cert = config.get_cert()
        if cert:
            session.cert = cert

        return session


# Global instance
tls_config_manager = TLSConfigManager()


def get_tls_config(db_session=None) -> TLSConfig:
    """Get the current TLS configuration."""
    return tls_config_manager.get_config(db_session)


def is_https_required(db_session=None) -> bool:
    """Check if HTTPS is required."""
    return tls_config_manager.is_https_required(db_session)


def normalize_url(url: str, db_session=None) -> str:
    """
    Normalize URL based on HTTPS-only setting.

    If HTTPS is required and URL starts with http://, convert to https://.
    If HTTPS is not required, return URL as-is.

    Args:
        url: The URL to normalize.
        db_session: Optional database session.

    Returns:
        Normalized URL.
    """
    if is_https_required(db_session):
        if url.startswith("http://"):
            return url.replace("http://", "https://", 1)
    return url


def create_tls_session(db_session=None, user_agent: str = None) -> requests.Session:
    """
    Create a requests Session with TLS configuration applied.

    This is the recommended way for scanner modules to create HTTP sessions
    with proper TLS/SSL configuration including:
    - Custom CA certificate support
    - Client certificate (mTLS) support
    - HTTPS-only enforcement

    Args:
        db_session: Optional database session for loading config.
        user_agent: Optional custom User-Agent header.

    Returns:
        Configured requests.Session instance.

    Example:
        from yads.core.tls_config import create_tls_session

        session = create_tls_session(db_session)
        response = session.get("https://internal.example.com/api")
    """
    session = requests.Session()

    # Apply TLS configuration
    tls_config_manager.apply_to_session(session, db_session)

    # Set default headers
    if user_agent:
        session.headers["User-Agent"] = user_agent
    else:
        session.headers["User-Agent"] = "YADS-Security-Scanner/1.15.0"

    return session


def get_request_kwargs(db_session=None) -> dict:
    """
    Get kwargs dict for requests calls with TLS settings.

    Use this when you need to pass verify/cert to individual requests
    rather than using a Session.

    Args:
        db_session: Optional database session for loading config.

    Returns:
        Dict with 'verify' and optionally 'cert' keys.

    Example:
        from yads.core.tls_config import get_request_kwargs

        kwargs = get_request_kwargs(db_session)
        response = requests.get(url, **kwargs)
    """
    config = get_tls_config(db_session)

    kwargs = {
        "verify": config.get_verify()
    }

    cert = config.get_cert()
    if cert:
        kwargs["cert"] = cert

    return kwargs
