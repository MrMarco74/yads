"""
Shared OSINT Utilities Module
=============================
Common utilities used by OSINT scanner modules including:
- OSINTQuotaManager: Quota checking and tracking
- RateLimitedClient: HTTP client with per-service rate limiting
- SecretPatterns: Regex patterns for secret detection
"""

import logging
import re
import time
import threading
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from datetime import datetime

import requests
from sqlmodel import Session

logger = logging.getLogger("yads.modules.osint_utils")


# =============================================================================
# Secret Detection Patterns
# =============================================================================

@dataclass
class SecretMatch:
    """Represents a detected secret."""
    pattern_name: str
    matched_text: str
    line_number: Optional[int] = None
    file_path: Optional[str] = None
    severity: str = "high"


class SecretPatterns:
    """
    Regex patterns for detecting secrets in code and text.
    Used by Social Media Scanner for GitHub secrets detection.
    """

    # Pattern definitions: (name, regex, severity)
    PATTERNS: List[tuple] = [
        # AWS
        ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", "critical"),
        ("AWS Secret Access Key", r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]", "critical"),

        # GitHub
        ("GitHub Token (ghp)", r"ghp_[a-zA-Z0-9]{36}", "critical"),
        ("GitHub Token (gho)", r"gho_[a-zA-Z0-9]{36}", "critical"),
        ("GitHub Token (ghu)", r"ghu_[a-zA-Z0-9]{36}", "critical"),
        ("GitHub Token (ghs)", r"ghs_[a-zA-Z0-9]{36}", "critical"),
        ("GitHub Token (ghr)", r"ghr_[a-zA-Z0-9]{36}", "critical"),
        ("GitHub Fine-grained PAT", r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}", "critical"),

        # Generic API Keys
        ("Generic API Key", r"(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_-]{20,}['\"]", "high"),
        ("Generic Secret", r"(?i)(secret|password|passwd|pwd)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]", "high"),
        ("Bearer Token", r"(?i)bearer\s+[a-zA-Z0-9_\-\.]+", "high"),

        # Google
        ("Google API Key", r"AIza[0-9A-Za-z_-]{35}", "high"),
        ("Google OAuth", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "medium"),

        # Slack
        ("Slack Token", r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*", "critical"),
        ("Slack Webhook", r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}", "high"),

        # Stripe
        ("Stripe Live Key", r"sk_live_[0-9a-zA-Z]{24}", "critical"),
        ("Stripe Test Key", r"sk_test_[0-9a-zA-Z]{24}", "medium"),

        # Private Keys
        ("Private Key", r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----", "critical"),

        # Database URLs
        ("Database URL", r"(?i)(postgres|mysql|mongodb|redis)://[^\s'\"]+", "high"),

        # JWT
        ("JWT Token", r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*", "medium"),

        # Twilio
        ("Twilio Account SID", r"AC[a-zA-Z0-9_\-]{32}", "high"),
        ("Twilio Auth Token", r"(?i)twilio(.{0,20})?['\"][a-f0-9]{32}['\"]", "high"),

        # SendGrid
        ("SendGrid API Key", r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", "high"),

        # Mailgun
        ("Mailgun API Key", r"key-[a-zA-Z0-9]{32}", "high"),

        # NPM
        ("NPM Token", r"npm_[A-Za-z0-9]{36}", "high"),

        # Heroku
        ("Heroku API Key", r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "medium"),
    ]

    _compiled_patterns: List[tuple] = None

    @classmethod
    def get_compiled_patterns(cls) -> List[tuple]:
        """Get compiled regex patterns (cached)."""
        if cls._compiled_patterns is None:
            cls._compiled_patterns = [
                (name, re.compile(pattern), severity)
                for name, pattern, severity in cls.PATTERNS
            ]
        return cls._compiled_patterns

    @classmethod
    def scan_text(cls, text: str, file_path: Optional[str] = None) -> List[SecretMatch]:
        """
        Scan text for secrets.

        Args:
            text: The text content to scan
            file_path: Optional file path for context

        Returns:
            List of SecretMatch objects for found secrets
        """
        findings = []
        lines = text.split('\n')

        for name, pattern, severity in cls.get_compiled_patterns():
            for line_num, line in enumerate(lines, 1):
                for match in pattern.finditer(line):
                    # Redact the actual secret value for storage
                    matched = match.group(0)
                    redacted = cls._redact_secret(matched)

                    findings.append(SecretMatch(
                        pattern_name=name,
                        matched_text=redacted,
                        line_number=line_num,
                        file_path=file_path,
                        severity=severity
                    ))

        return findings

    @classmethod
    def _redact_secret(cls, secret: str) -> str:
        """Redact a secret for safe storage, keeping first/last few chars."""
        if len(secret) <= 10:
            return "*" * len(secret)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]


# =============================================================================
# OSINT Quota Manager
# =============================================================================

class OSINTQuotaManager:
    """
    Manages OSINT quota checking and tracking for tenants.

    Usage:
        quota_mgr = OSINTQuotaManager(db_session, tenant_id)
        if quota_mgr.can_use(cost=1):
            # Perform OSINT operation
            quota_mgr.consume(cost=1)
    """

    def __init__(self, db_session: Session, tenant_id: int):
        self.db = db_session
        self.tenant_id = tenant_id
        self._tenant = None

    def _get_tenant(self):
        """Lazy load tenant."""
        if self._tenant is None:
            from yads.models import Tenant
            self._tenant = self.db.get(Tenant, self.tenant_id)
        return self._tenant

    def is_enabled(self) -> bool:
        """Check if OSINT is enabled for this tenant."""
        tenant = self._get_tenant()
        if not tenant:
            return False
        return tenant.osint_enabled

    def get_remaining_quota(self) -> int:
        """Get remaining OSINT quota."""
        tenant = self._get_tenant()
        if not tenant:
            return 0
        return max(0, tenant.osint_quota_max - tenant.osint_quota_used)

    def can_use(self, cost: int = 1) -> bool:
        """Check if quota is available for an operation."""
        if not self.is_enabled():
            return False
        return self.get_remaining_quota() >= cost

    def consume(self, cost: int = 1) -> bool:
        """
        Consume quota points.

        Returns:
            True if consumption was successful, False if insufficient quota.
        """
        if not self.can_use(cost):
            return False

        tenant = self._get_tenant()
        if tenant:
            tenant.osint_quota_used += cost
            self.db.add(tenant)
            self.db.commit()
            self.db.refresh(tenant)
            return True
        return False

    def get_status(self) -> Dict[str, Any]:
        """Get quota status information."""
        tenant = self._get_tenant()
        if not tenant:
            return {
                "enabled": False,
                "quota_max": 0,
                "quota_used": 0,
                "quota_remaining": 0,
                "cost_per_search": 0.0
            }
        return {
            "enabled": tenant.osint_enabled,
            "quota_max": tenant.osint_quota_max,
            "quota_used": tenant.osint_quota_used,
            "quota_remaining": self.get_remaining_quota(),
            "cost_per_search": tenant.osint_cost_per_search
        }


# =============================================================================
# Rate Limited HTTP Client
# =============================================================================

class RateLimitedClient:
    """
    HTTP client with per-service rate limiting and custom TLS support.

    Thread-safe rate limiting using a simple token bucket approach.
    Supports custom CA certificates and client certificates for scanning
    internal infrastructure behind corporate PKI.

    Usage:
        client = RateLimitedClient()

        # Register rate limits for different services
        client.register_service("hibp", requests_per_second=0.6)  # 1 req / 1.6s
        client.register_service("hunter", requests_per_minute=10)
        client.register_service("github", requests_per_hour=5000)

        # Make rate-limited requests
        response = client.get("hibp", "https://haveibeenpwned.com/api/v3/...")
    """

    def __init__(self, default_timeout: int = 30, db_session: Session = None):
        self.default_timeout = default_timeout
        self.db_session = db_session
        self._locks: Dict[str, threading.Lock] = {}
        self._last_request: Dict[str, float] = {}
        self._min_intervals: Dict[str, float] = {}
        self._session = requests.Session()
        self._https_only = False

        # Set default headers
        self._session.headers.update({
            "User-Agent": "YADS-Security-Scanner/1.15.0"
        })

        # Apply TLS configuration
        self._apply_tls_config()

    def _apply_tls_config(self):
        """Apply TLS configuration from database/environment."""
        try:
            from yads.core.tls_config import tls_config_manager

            config = tls_config_manager.get_config(self.db_session)

            # Apply to session
            self._session.verify = config.get_verify()

            cert = config.get_cert()
            if cert:
                self._session.cert = cert
                logger.info(f"TLS client certificate configured: {cert[0]}")

            if config.custom_ca_cert_path:
                logger.info(f"Custom CA certificate configured: {config.custom_ca_cert_path}")

            self._https_only = config.https_only

        except Exception as e:
            logger.debug(f"Could not apply TLS config: {e}")

    def _normalize_url(self, url: str) -> str:
        """Normalize URL based on HTTPS-only setting."""
        if self._https_only and url.startswith("http://"):
            logger.debug(f"HTTPS-only: Converting {url} to HTTPS")
            return url.replace("http://", "https://", 1)
        return url

    def register_service(
        self,
        service_name: str,
        requests_per_second: Optional[float] = None,
        requests_per_minute: Optional[float] = None,
        requests_per_hour: Optional[float] = None
    ):
        """
        Register a service with its rate limit.

        Only one of the rate parameters should be provided.
        """
        self._locks[service_name] = threading.Lock()
        self._last_request[service_name] = 0

        if requests_per_second:
            self._min_intervals[service_name] = 1.0 / requests_per_second
        elif requests_per_minute:
            self._min_intervals[service_name] = 60.0 / requests_per_minute
        elif requests_per_hour:
            self._min_intervals[service_name] = 3600.0 / requests_per_hour
        else:
            # No rate limiting
            self._min_intervals[service_name] = 0

    def _wait_for_rate_limit(self, service_name: str):
        """Wait if necessary to respect rate limits."""
        if service_name not in self._min_intervals:
            return

        with self._locks.get(service_name, threading.Lock()):
            min_interval = self._min_intervals[service_name]
            if min_interval <= 0:
                return

            elapsed = time.time() - self._last_request.get(service_name, 0)
            if elapsed < min_interval:
                sleep_time = min_interval - elapsed
                logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s for {service_name}")
                time.sleep(sleep_time)

            self._last_request[service_name] = time.time()

    def get(
        self,
        service_name: str,
        url: str,
        headers: Optional[Dict] = None,
        timeout: Optional[int] = None,
        **kwargs
    ) -> requests.Response:
        """Make a rate-limited GET request with TLS support."""
        self._wait_for_rate_limit(service_name)
        url = self._normalize_url(url)
        return self._session.get(
            url,
            headers=headers,
            timeout=timeout or self.default_timeout,
            **kwargs
        )

    def post(
        self,
        service_name: str,
        url: str,
        headers: Optional[Dict] = None,
        timeout: Optional[int] = None,
        **kwargs
    ) -> requests.Response:
        """Make a rate-limited POST request with TLS support."""
        self._wait_for_rate_limit(service_name)
        url = self._normalize_url(url)
        return self._session.post(
            url,
            headers=headers,
            timeout=timeout or self.default_timeout,
            **kwargs
        )

    def head(
        self,
        service_name: str,
        url: str,
        headers: Optional[Dict] = None,
        timeout: Optional[int] = None,
        **kwargs
    ) -> requests.Response:
        """Make a rate-limited HEAD request with TLS support."""
        self._wait_for_rate_limit(service_name)
        url = self._normalize_url(url)
        return self._session.head(
            url,
            headers=headers,
            timeout=timeout or self.default_timeout,
            **kwargs
        )


# =============================================================================
# Domain Variation Generators (for Brand Intelligence)
# =============================================================================

class DomainVariationGenerator:
    """
    Generates domain variations for brand intelligence scanning.
    Extends basic typosquatting with homoglyphs, bitsquatting, and combosquatting.
    """

    # Homoglyph mappings (characters that look similar)
    HOMOGLYPHS = {
        'a': ['4', '@', 'a', 'q'],
        'b': ['6', 'd', 'lb'],
        'c': ['(', 'k', 's'],
        'd': ['b', 'cl', 'di'],
        'e': ['3', 'ee'],
        'f': ['ph'],
        'g': ['9', 'q'],
        'h': ['lh', 'n'],
        'i': ['1', 'l', '!', 'j'],
        'j': ['i'],
        'k': ['c', 'lk'],
        'l': ['1', 'i', '|'],
        'm': ['nn', 'rn', 'rr'],
        'n': ['m', 'r'],
        'o': ['0', 'q'],
        'p': ['q'],
        'q': ['g', 'p'],
        'r': ['n'],
        's': ['5', '$', 'z'],
        't': ['7', '+'],
        'u': ['v', 'uu'],
        'v': ['u', 'w'],
        'w': ['vv', 'uu'],
        'x': ['ks'],
        'y': ['i'],
        'z': ['2', 's'],
    }

    # Common prefix/suffix for combosquatting
    COMBO_PREFIXES = [
        'www-', 'ww-', 'login-', 'signin-', 'secure-', 'account-',
        'my-', 'mail-', 'webmail-', 'portal-', 'online-', 'go-',
        'auth-', 'service-', 'support-', 'help-', 'verify-'
    ]

    COMBO_SUFFIXES = [
        '-login', '-signin', '-secure', '-account', '-verify',
        '-auth', '-support', '-help', '-service', '-online',
        '-portal', '-web', '-mail', '-app', '-mobile', '-uk',
        '-us', '-de', '-fr', '-int'
    ]

    @classmethod
    def generate_homoglyphs(cls, domain: str, max_variations: int = 50) -> List[str]:
        """Generate homoglyph variations of a domain."""
        variations = set()
        name, tld = domain.rsplit('.', 1) if '.' in domain else (domain, 'com')

        # Single character replacements
        for i, char in enumerate(name.lower()):
            if char in cls.HOMOGLYPHS:
                for replacement in cls.HOMOGLYPHS[char]:
                    variation = name[:i] + replacement + name[i+1:]
                    variations.add(f"{variation}.{tld}")
                    if len(variations) >= max_variations:
                        return list(variations)

        return list(variations)

    @classmethod
    def generate_bitsquats(cls, domain: str) -> List[str]:
        """
        Generate bitsquatting variations.
        Bitsquatting exploits random bit-errors in DNS lookups.
        """
        variations = set()
        name, tld = domain.rsplit('.', 1) if '.' in domain else (domain, 'com')

        for i, char in enumerate(name.lower()):
            # Flip each bit
            char_code = ord(char)
            for bit in range(8):
                flipped = char_code ^ (1 << bit)
                # Only keep valid lowercase letters
                if 97 <= flipped <= 122:  # a-z
                    variation = name[:i] + chr(flipped) + name[i+1:]
                    if variation != name:
                        variations.add(f"{variation}.{tld}")

        return list(variations)

    @classmethod
    def generate_combosquats(cls, domain: str) -> List[str]:
        """
        Generate combosquatting variations.
        Adds common prefixes/suffixes to the domain.
        """
        variations = []
        name, tld = domain.rsplit('.', 1) if '.' in domain else (domain, 'com')

        for prefix in cls.COMBO_PREFIXES:
            variations.append(f"{prefix}{name}.{tld}")

        for suffix in cls.COMBO_SUFFIXES:
            variations.append(f"{name}{suffix}.{tld}")

        return variations

    @classmethod
    def generate_all_variations(
        cls,
        domain: str,
        include_homoglyphs: bool = True,
        include_bitsquats: bool = True,
        include_combosquats: bool = True,
        max_total: int = 200
    ) -> List[str]:
        """Generate all types of domain variations."""
        variations = set()

        if include_homoglyphs:
            variations.update(cls.generate_homoglyphs(domain))

        if include_bitsquats:
            variations.update(cls.generate_bitsquats(domain))

        if include_combosquats:
            variations.update(cls.generate_combosquats(domain))

        # Remove original domain
        variations.discard(domain)

        # Limit total variations
        result = list(variations)
        if len(result) > max_total:
            result = result[:max_total]

        return result


# =============================================================================
# Email Pattern Detector (for Email Intelligence)
# =============================================================================

class EmailPatternDetector:
    """
    Detects email address patterns from discovered emails.
    """

    # Common email patterns to test
    PATTERNS = [
        ("first.last", "{first}.{last}@{domain}"),
        ("firstlast", "{first}{last}@{domain}"),
        ("first_last", "{first}_{last}@{domain}"),
        ("f.last", "{f}.{last}@{domain}"),
        ("flast", "{f}{last}@{domain}"),
        ("first.l", "{first}.{l}@{domain}"),
        ("firstl", "{first}{l}@{domain}"),
        ("first", "{first}@{domain}"),
        ("last.first", "{last}.{first}@{domain}"),
    ]

    @classmethod
    def detect_pattern(cls, emails: List[str], domain: str) -> Optional[Dict[str, Any]]:
        """
        Analyze a list of emails to detect the naming pattern.

        Returns:
            Dict with pattern name, format, and confidence score.
        """
        if not emails:
            return None

        # Extract local parts for the target domain
        local_parts = []
        for email in emails:
            if '@' in email:
                local, email_domain = email.lower().split('@', 1)
                if email_domain == domain.lower():
                    local_parts.append(local)

        if len(local_parts) < 2:
            return None

        # Analyze patterns
        pattern_scores = {}

        # Check for dots
        has_dots = sum(1 for lp in local_parts if '.' in lp)
        has_underscores = sum(1 for lp in local_parts if '_' in lp)

        if has_dots > len(local_parts) * 0.5:
            if all(lp.count('.') == 1 for lp in local_parts if '.' in lp):
                # Likely first.last or similar
                pattern_scores["first.last"] = 0.8
        elif has_underscores > len(local_parts) * 0.5:
            pattern_scores["first_last"] = 0.8
        else:
            # Check length patterns
            avg_len = sum(len(lp) for lp in local_parts) / len(local_parts)
            if avg_len < 10:
                pattern_scores["flast"] = 0.6
            else:
                pattern_scores["firstlast"] = 0.6

        if not pattern_scores:
            return None

        # Return highest scoring pattern
        best_pattern = max(pattern_scores, key=pattern_scores.get)

        return {
            "pattern": best_pattern,
            "format": next(fmt for name, fmt in cls.PATTERNS if name == best_pattern),
            "confidence": pattern_scores[best_pattern],
            "sample_count": len(local_parts)
        }

    @classmethod
    def generate_emails(
        cls,
        names: List[Dict[str, str]],
        domain: str,
        pattern: str = "first.last"
    ) -> List[str]:
        """
        Generate potential emails from names using a pattern.

        Args:
            names: List of dicts with 'first' and 'last' keys
            domain: Target domain
            pattern: Pattern name to use

        Returns:
            List of generated email addresses
        """
        emails = []
        fmt = next((f for n, f in cls.PATTERNS if n == pattern), "{first}.{last}@{domain}")

        for name in names:
            first = name.get('first', '').lower().strip()
            last = name.get('last', '').lower().strip()

            if not first and not last:
                continue

            email = fmt.format(
                first=first,
                last=last,
                f=first[0] if first else '',
                l=last[0] if last else '',
                domain=domain
            )

            # Clean up any double characters from missing names
            email = email.replace('..', '.').replace('@@', '@')
            emails.append(email)

        return emails
