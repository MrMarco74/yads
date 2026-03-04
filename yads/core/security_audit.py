"""
Security Audit Logging System

Provides comprehensive security event logging aligned with MITRE ATT&CK framework.
Logs to both database (for persistence/querying) and Splunk (for SIEM integration).

MITRE ATT&CK Coverage:
- TA0001 Initial Access: T1078 (Valid Accounts)
- TA0003 Persistence: T1098 (Account Manipulation), T1136 (Create Account)
- TA0004 Privilege Escalation: T1078.003 (Local Accounts)
- TA0005 Defense Evasion: T1070.001 (Clear Logs)
- TA0006 Credential Access: T1110 (Brute Force), T1556 (Modify Auth Process)
- TA0007 Discovery: T1087 (Account Discovery)
- TA0040 Impact: T1531 (Account Access Removal)
"""

import logging
import json
from datetime import datetime
from typing import Optional, Dict, Any
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger("yads.security_audit")


class SecurityEventType(str, Enum):
    """Security event types for audit logging."""
    # Authentication Events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGIN_FAILURE_INVALID_USER = "login_failure_invalid_user"
    LOGIN_FAILURE_INVALID_PASSWORD = "login_failure_invalid_password"
    LOGIN_FAILURE_INACTIVE_USER = "login_failure_inactive_user"
    LOGIN_FAILURE_MFA_REQUIRED = "login_failure_mfa_required"
    LOGIN_FAILURE_MFA_INVALID = "login_failure_mfa_invalid"
    LOGOUT = "logout"
    SESSION_EXPIRED = "session_expired"

    # Password Events
    PASSWORD_CHANGE = "password_change"
    PASSWORD_CHANGE_FORCED = "password_change_forced"
    PASSWORD_RESET_BY_ADMIN = "password_reset_by_admin"

    # MFA Events
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    MFA_RESET_BY_ADMIN = "mfa_reset_by_admin"
    MFA_RESET_BY_USER = "mfa_reset_by_user"

    # User Management Events
    USER_CREATED = "user_created"
    USER_DELETED = "user_deleted"
    USER_MODIFIED = "user_modified"
    USER_ROLE_CHANGED = "user_role_changed"
    USER_ACTIVATED = "user_activated"
    USER_DEACTIVATED = "user_deactivated"

    # Tenant/Authorization Events
    TENANT_SWITCH = "tenant_switch"
    TENANT_ACCESS_GRANTED = "tenant_access_granted"
    TENANT_ACCESS_REVOKED = "tenant_access_revoked"

    # Session Events
    SESSION_TIMEOUT_CHANGED = "session_timeout_changed"

    # Permission Events
    PERMISSION_DENIED = "permission_denied"
    PRIVILEGE_ESCALATION_ATTEMPT = "privilege_escalation_attempt"

    # API Key Events
    API_KEY_CREATED = "api_key_created"
    API_KEY_ROTATED = "api_key_rotated"
    API_KEY_REVOKED = "api_key_revoked"
    API_KEY_USED = "api_key_used"

    # System Events
    SYSTEM_CONFIG_CHANGED = "system_config_changed"
    LICENSE_APPLIED = "license_applied"
    LICENSE_EXPIRED = "license_expired"
    BACKUP_CREATED = "backup_created"
    BACKUP_RESTORED = "backup_restored"


@dataclass
class MITREMapping:
    """MITRE ATT&CK mapping for security events."""
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str


# MITRE ATT&CK mappings for each event type
MITRE_MAPPINGS: Dict[SecurityEventType, MITREMapping] = {
    # Authentication - TA0001 Initial Access
    SecurityEventType.LOGIN_SUCCESS: MITREMapping(
        "TA0001", "Initial Access", "T1078", "Valid Accounts"
    ),
    SecurityEventType.LOGIN_FAILURE: MITREMapping(
        "TA0006", "Credential Access", "T1110", "Brute Force"
    ),
    SecurityEventType.LOGIN_FAILURE_INVALID_USER: MITREMapping(
        "TA0006", "Credential Access", "T1110.001", "Brute Force: Password Guessing"
    ),
    SecurityEventType.LOGIN_FAILURE_INVALID_PASSWORD: MITREMapping(
        "TA0006", "Credential Access", "T1110.001", "Brute Force: Password Guessing"
    ),
    SecurityEventType.LOGIN_FAILURE_INACTIVE_USER: MITREMapping(
        "TA0001", "Initial Access", "T1078.003", "Valid Accounts: Local Accounts"
    ),
    SecurityEventType.LOGIN_FAILURE_MFA_REQUIRED: MITREMapping(
        "TA0006", "Credential Access", "T1556.006", "Modify Auth Process: MFA"
    ),
    SecurityEventType.LOGIN_FAILURE_MFA_INVALID: MITREMapping(
        "TA0006", "Credential Access", "T1556.006", "Modify Auth Process: MFA"
    ),
    SecurityEventType.LOGOUT: MITREMapping(
        "TA0005", "Defense Evasion", "T1070", "Indicator Removal"
    ),
    SecurityEventType.SESSION_EXPIRED: MITREMapping(
        "TA0001", "Initial Access", "T1078", "Valid Accounts"
    ),

    # Password Events - TA0006 Credential Access
    SecurityEventType.PASSWORD_CHANGE: MITREMapping(
        "TA0006", "Credential Access", "T1556", "Modify Authentication Process"
    ),
    SecurityEventType.PASSWORD_CHANGE_FORCED: MITREMapping(
        "TA0006", "Credential Access", "T1556", "Modify Authentication Process"
    ),
    SecurityEventType.PASSWORD_RESET_BY_ADMIN: MITREMapping(
        "TA0003", "Persistence", "T1098", "Account Manipulation"
    ),

    # MFA Events - TA0006 Credential Access
    SecurityEventType.MFA_ENABLED: MITREMapping(
        "TA0006", "Credential Access", "T1556.006", "Modify Auth Process: MFA"
    ),
    SecurityEventType.MFA_DISABLED: MITREMapping(
        "TA0006", "Credential Access", "T1556.006", "Modify Auth Process: MFA"
    ),
    SecurityEventType.MFA_RESET_BY_ADMIN: MITREMapping(
        "TA0003", "Persistence", "T1098", "Account Manipulation"
    ),
    SecurityEventType.MFA_RESET_BY_USER: MITREMapping(
        "TA0006", "Credential Access", "T1556.006", "Modify Auth Process: MFA"
    ),

    # User Management - TA0003 Persistence
    SecurityEventType.USER_CREATED: MITREMapping(
        "TA0003", "Persistence", "T1136", "Create Account"
    ),
    SecurityEventType.USER_DELETED: MITREMapping(
        "TA0040", "Impact", "T1531", "Account Access Removal"
    ),
    SecurityEventType.USER_MODIFIED: MITREMapping(
        "TA0003", "Persistence", "T1098", "Account Manipulation"
    ),
    SecurityEventType.USER_ROLE_CHANGED: MITREMapping(
        "TA0004", "Privilege Escalation", "T1078.003", "Valid Accounts: Local Accounts"
    ),
    SecurityEventType.USER_ACTIVATED: MITREMapping(
        "TA0003", "Persistence", "T1098", "Account Manipulation"
    ),
    SecurityEventType.USER_DEACTIVATED: MITREMapping(
        "TA0040", "Impact", "T1531", "Account Access Removal"
    ),

    # Tenant/Authorization - TA0007 Discovery
    SecurityEventType.TENANT_SWITCH: MITREMapping(
        "TA0007", "Discovery", "T1087", "Account Discovery"
    ),
    SecurityEventType.TENANT_ACCESS_GRANTED: MITREMapping(
        "TA0003", "Persistence", "T1098", "Account Manipulation"
    ),
    SecurityEventType.TENANT_ACCESS_REVOKED: MITREMapping(
        "TA0040", "Impact", "T1531", "Account Access Removal"
    ),

    # Session Events
    SecurityEventType.SESSION_TIMEOUT_CHANGED: MITREMapping(
        "TA0005", "Defense Evasion", "T1562", "Impair Defenses"
    ),

    # Permission Events
    SecurityEventType.PERMISSION_DENIED: MITREMapping(
        "TA0007", "Discovery", "T1087", "Account Discovery"
    ),
    SecurityEventType.PRIVILEGE_ESCALATION_ATTEMPT: MITREMapping(
        "TA0004", "Privilege Escalation", "T1078", "Valid Accounts"
    ),

    # API Key Events
    SecurityEventType.API_KEY_CREATED: MITREMapping(
        "TA0003", "Persistence", "T1098.001", "Account Manipulation: Additional Cloud Credentials"
    ),
    SecurityEventType.API_KEY_ROTATED: MITREMapping(
        "TA0006", "Credential Access", "T1556", "Modify Authentication Process"
    ),
    SecurityEventType.API_KEY_REVOKED: MITREMapping(
        "TA0040", "Impact", "T1531", "Account Access Removal"
    ),
    SecurityEventType.API_KEY_USED: MITREMapping(
        "TA0001", "Initial Access", "T1078", "Valid Accounts"
    ),

    # System Events
    SecurityEventType.SYSTEM_CONFIG_CHANGED: MITREMapping(
        "TA0005", "Defense Evasion", "T1562", "Impair Defenses"
    ),
    SecurityEventType.LICENSE_APPLIED: MITREMapping(
        "TA0003", "Persistence", "T1543", "Create or Modify System Process"
    ),
    SecurityEventType.LICENSE_EXPIRED: MITREMapping(
        "TA0040", "Impact", "T1489", "Service Stop"
    ),
    SecurityEventType.BACKUP_CREATED: MITREMapping(
        "TA0009", "Collection", "T1560", "Archive Collected Data"
    ),
    SecurityEventType.BACKUP_RESTORED: MITREMapping(
        "TA0005", "Defense Evasion", "T1070", "Indicator Removal"
    ),
}


class SecurityAuditLogger:
    """
    Security audit logger that persists events to database and forwards to Splunk.

    Usage:
        from yads.core.security_audit import audit_log

        audit_log.log(
            event_type=SecurityEventType.LOGIN_SUCCESS,
            username="admin",
            source_ip="192.168.1.1",
            details={"method": "password"}
        )
    """

    def __init__(self):
        self._splunk_logger = None
        self._metrics = None
        self._initialized = False

    def _lazy_init(self):
        """Lazy initialization to avoid circular imports."""
        if self._initialized:
            return

        try:
            from yads.core.splunk_logger import splunk_logger
            self._splunk_logger = splunk_logger
        except Exception as e:
            logger.warning(f"Could not initialize Splunk logger: {e}")

        try:
            from yads.core.metrics import get_metrics
            self._metrics = get_metrics()
        except Exception as e:
            logger.warning(f"Could not initialize Prometheus metrics: {e}")
            self._metrics = None

        self._initialized = True

    def log(
        self,
        event_type: SecurityEventType,
        username: Optional[str] = None,
        user_id: Optional[int] = None,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        tenant_id: Optional[int] = None,
        target_user: Optional[str] = None,
        target_user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
        session = None
    ) -> None:
        """
        Log a security event.

        Args:
            event_type: Type of security event
            username: Username of the actor (who performed the action)
            user_id: User ID of the actor
            source_ip: Client IP address
            user_agent: Client user agent string
            tenant_id: Tenant context
            target_user: Username of the target (for admin actions)
            target_user_id: User ID of the target
            details: Additional event details
            success: Whether the action was successful
            session: Optional database session for persistence
        """
        self._lazy_init()

        # Get MITRE mapping
        mitre = MITRE_MAPPINGS.get(event_type)

        # Build event record
        event_data = {
            "event_type": event_type.value,
            "timestamp": datetime.utcnow().isoformat(),
            "username": username or "anonymous",
            "user_id": user_id,
            "source_ip": source_ip or "unknown",
            "user_agent": user_agent,
            "tenant_id": tenant_id,
            "target_user": target_user,
            "target_user_id": target_user_id,
            "success": success,
            "details": details or {},
        }

        if mitre:
            event_data["mitre_tactic_id"] = mitre.tactic_id
            event_data["mitre_tactic_name"] = mitre.tactic_name
            event_data["mitre_technique_id"] = mitre.technique_id
            event_data["mitre_technique_name"] = mitre.technique_name

        # Log to Python logger (will go to file logs)
        log_level = logging.INFO if success else logging.WARNING
        logger.log(
            log_level,
            f"[{event_type.value}] user={username} ip={source_ip} "
            f"target={target_user} success={success} "
            f"mitre={mitre.technique_id if mitre else 'N/A'}"
        )

        # Persist to database if session provided
        if session:
            try:
                self._persist_to_db(session, event_data, event_type, mitre)
            except Exception as e:
                logger.error(f"Failed to persist audit log to database: {e}")

        # Forward to Splunk
        if self._splunk_logger and self._splunk_logger.enabled:
            try:
                self._splunk_logger.send_security_event(
                    action=event_type.value,
                    user=username or "anonymous",
                    mitre_id=mitre.technique_id if mitre else "T0000",
                    details={
                        **event_data,
                        "mitre_tactic_id": mitre.tactic_id if mitre else None,
                        "mitre_tactic_name": mitre.tactic_name if mitre else None,
                        "mitre_technique_name": mitre.technique_name if mitre else None,
                    },
                    tenant_id=tenant_id
                )
            except Exception as e:
                logger.error(f"Failed to send audit log to Splunk: {e}")

        # Record to Prometheus metrics
        if self._metrics:
            try:
                self._metrics.record_security_event(
                    event_type=event_type.value,
                    success=success
                )
            except Exception as e:
                logger.debug(f"Failed to record security event metric: {e}")

    def _persist_to_db(self, session, event_data: Dict, event_type: SecurityEventType, mitre: Optional[MITREMapping]):
        """Persist audit event to database."""
        from yads.models import SecurityAuditLog

        audit_record = SecurityAuditLog(
            event_type=event_type.value,
            username=event_data.get("username"),
            user_id=event_data.get("user_id"),
            source_ip=event_data.get("source_ip"),
            user_agent=event_data.get("user_agent"),
            tenant_id=event_data.get("tenant_id"),
            target_user=event_data.get("target_user"),
            target_user_id=event_data.get("target_user_id"),
            success=event_data.get("success", True),
            details=event_data.get("details"),
            mitre_tactic_id=mitre.tactic_id if mitre else None,
            mitre_technique_id=mitre.technique_id if mitre else None,
        )
        session.add(audit_record)
        # Note: Caller should commit the session

    def log_from_request(
        self,
        request,
        event_type: SecurityEventType,
        username: Optional[str] = None,
        user_id: Optional[int] = None,
        tenant_id: Optional[int] = None,
        target_user: Optional[str] = None,
        target_user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
        session = None
    ) -> None:
        """
        Log a security event, extracting IP and user agent from the request.

        Args:
            request: FastAPI Request object
            event_type: Type of security event
            ... (other args same as log())
        """
        # Extract client IP (handle proxies)
        source_ip = None
        if request:
            # Check for forwarded headers (reverse proxy)
            forwarded_for = request.headers.get("X-Forwarded-For")
            if forwarded_for:
                source_ip = forwarded_for.split(",")[0].strip()
            else:
                source_ip = request.client.host if request.client else None

        # Extract user agent
        user_agent = None
        if request:
            user_agent = request.headers.get("User-Agent")

        self.log(
            event_type=event_type,
            username=username,
            user_id=user_id,
            source_ip=source_ip,
            user_agent=user_agent,
            tenant_id=tenant_id,
            target_user=target_user,
            target_user_id=target_user_id,
            details=details,
            success=success,
            session=session
        )


# Singleton instance
audit_log = SecurityAuditLogger()


# Convenience functions for common events
def log_login_success(request, user, session=None):
    """Log successful login."""
    audit_log.log_from_request(
        request=request,
        event_type=SecurityEventType.LOGIN_SUCCESS,
        username=user.username,
        user_id=user.id,
        tenant_id=user.tenant_id,
        details={"mfa_enabled": user.mfa_enabled},
        session=session
    )


def log_login_failure(request, username: str, reason: str, session=None):
    """Log failed login attempt."""
    event_type = SecurityEventType.LOGIN_FAILURE
    if reason == "invalid_user":
        event_type = SecurityEventType.LOGIN_FAILURE_INVALID_USER
    elif reason == "invalid_password":
        event_type = SecurityEventType.LOGIN_FAILURE_INVALID_PASSWORD
    elif reason == "inactive":
        event_type = SecurityEventType.LOGIN_FAILURE_INACTIVE_USER
    elif reason == "mfa_required":
        event_type = SecurityEventType.LOGIN_FAILURE_MFA_REQUIRED
    elif reason == "mfa_invalid":
        event_type = SecurityEventType.LOGIN_FAILURE_MFA_INVALID

    audit_log.log_from_request(
        request=request,
        event_type=event_type,
        username=username,
        details={"reason": reason},
        success=False,
        session=session
    )


def log_logout(request, user, session=None):
    """Log user logout."""
    audit_log.log_from_request(
        request=request,
        event_type=SecurityEventType.LOGOUT,
        username=user.username if user else None,
        user_id=user.id if user else None,
        tenant_id=user.tenant_id if user else None,
        session=session
    )


def log_password_change(request, user, changed_by_admin: bool = False, admin_user=None, session=None):
    """Log password change."""
    if changed_by_admin:
        audit_log.log_from_request(
            request=request,
            event_type=SecurityEventType.PASSWORD_RESET_BY_ADMIN,
            username=admin_user.username if admin_user else "admin",
            user_id=admin_user.id if admin_user else None,
            tenant_id=admin_user.tenant_id if admin_user else None,
            target_user=user.username,
            target_user_id=user.id,
            session=session
        )
    else:
        audit_log.log_from_request(
            request=request,
            event_type=SecurityEventType.PASSWORD_CHANGE,
            username=user.username,
            user_id=user.id,
            tenant_id=user.tenant_id,
            session=session
        )


def log_mfa_event(request, user, event: str, by_admin: bool = False, admin_user=None, session=None):
    """Log MFA-related events."""
    event_type_map = {
        "enabled": SecurityEventType.MFA_ENABLED,
        "disabled": SecurityEventType.MFA_DISABLED,
        "reset_by_admin": SecurityEventType.MFA_RESET_BY_ADMIN,
        "reset_by_user": SecurityEventType.MFA_RESET_BY_USER,
    }

    event_type = event_type_map.get(event, SecurityEventType.MFA_DISABLED)

    if by_admin:
        audit_log.log_from_request(
            request=request,
            event_type=event_type,
            username=admin_user.username if admin_user else "admin",
            user_id=admin_user.id if admin_user else None,
            tenant_id=admin_user.tenant_id if admin_user else None,
            target_user=user.username,
            target_user_id=user.id,
            session=session
        )
    else:
        audit_log.log_from_request(
            request=request,
            event_type=event_type,
            username=user.username,
            user_id=user.id,
            tenant_id=user.tenant_id,
            session=session
        )


def log_user_created(request, new_user, created_by, session=None):
    """Log user creation."""
    audit_log.log_from_request(
        request=request,
        event_type=SecurityEventType.USER_CREATED,
        username=created_by.username,
        user_id=created_by.id,
        tenant_id=created_by.tenant_id,
        target_user=new_user.username,
        target_user_id=new_user.id,
        details={
            "new_user_role": new_user.role,
            "new_user_tenant_id": new_user.tenant_id,
            "force_password_change": new_user.force_password_change,
        },
        session=session
    )


def log_user_deleted(request, deleted_user, deleted_by, session=None):
    """Log user deletion."""
    audit_log.log_from_request(
        request=request,
        event_type=SecurityEventType.USER_DELETED,
        username=deleted_by.username,
        user_id=deleted_by.id,
        tenant_id=deleted_by.tenant_id,
        target_user=deleted_user.username,
        target_user_id=deleted_user.id,
        details={"deleted_user_role": deleted_user.role},
        session=session
    )


def log_user_modified(request, user, modified_by, changes: Dict[str, Any], session=None):
    """Log user modification."""
    audit_log.log_from_request(
        request=request,
        event_type=SecurityEventType.USER_MODIFIED,
        username=modified_by.username,
        user_id=modified_by.id,
        tenant_id=modified_by.tenant_id,
        target_user=user.username,
        target_user_id=user.id,
        details={"changes": changes},
        session=session
    )


def log_role_change(request, user, old_role: str, new_role: str, changed_by, session=None):
    """Log role change (privilege escalation/de-escalation)."""
    audit_log.log_from_request(
        request=request,
        event_type=SecurityEventType.USER_ROLE_CHANGED,
        username=changed_by.username,
        user_id=changed_by.id,
        tenant_id=changed_by.tenant_id,
        target_user=user.username,
        target_user_id=user.id,
        details={"old_role": old_role, "new_role": new_role},
        session=session
    )


def log_tenant_switch(request, user, old_tenant_id, new_tenant_id, session=None):
    """Log tenant context switch."""
    audit_log.log_from_request(
        request=request,
        event_type=SecurityEventType.TENANT_SWITCH,
        username=user.username,
        user_id=user.id,
        tenant_id=new_tenant_id,
        details={
            "old_tenant_id": old_tenant_id,
            "new_tenant_id": new_tenant_id,
        },
        session=session
    )


def log_permission_denied(request, user, action: str, resource: str = None, session=None):
    """Log permission denied event."""
    audit_log.log_from_request(
        request=request,
        event_type=SecurityEventType.PERMISSION_DENIED,
        username=user.username if user else "anonymous",
        user_id=user.id if user else None,
        tenant_id=user.tenant_id if user else None,
        details={"action": action, "resource": resource},
        success=False,
        session=session
    )


def log_session_timeout_change(request, user, old_timeout: int, new_timeout: int, session=None):
    """Log session timeout configuration change."""
    audit_log.log_from_request(
        request=request,
        event_type=SecurityEventType.SESSION_TIMEOUT_CHANGED,
        username=user.username,
        user_id=user.id,
        tenant_id=user.tenant_id,
        details={
            "old_timeout_minutes": old_timeout,
            "new_timeout_minutes": new_timeout,
        },
        session=session
    )


def log_system_config_change(request, user, config_key: str, old_value: Any, new_value: Any, session=None):
    """Log system configuration change."""
    audit_log.log_from_request(
        request=request,
        event_type=SecurityEventType.SYSTEM_CONFIG_CHANGED,
        username=user.username,
        user_id=user.id,
        tenant_id=user.tenant_id,
        details={
            "config_key": config_key,
            "old_value": str(old_value) if old_value is not None else None,
            "new_value": str(new_value),
        },
        session=session
    )


def log_api_key_access(request, api_key_record, success: bool = True, session=None):
    """Log access via API Key."""
    details = {
        "key_id": api_key_record.id,
        "key_name": api_key_record.name,
        "key_prefix": api_key_record.key_prefix,
        "endpoint": str(request.url),
        "method": request.method
    }
    audit_log.log_from_request(
        request=request,
        event_type=SecurityEventType.API_KEY_USED,
        username=f"apikey:{api_key_record.id}",
        tenant_id=api_key_record.tenant_id,
        details=details,
        success=success,
        session=session
    )
