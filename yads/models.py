from datetime import datetime
from typing import Optional, List
from sqlmodel import SQLModel, Field, Relationship
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import Column, String, Text


class UserTenantLink(SQLModel, table=True):
    user_id: Optional[int] = Field(default=None, foreign_key="user.id", primary_key=True)
    tenant_id: Optional[int] = Field(default=None, foreign_key="tenant.id", primary_key=True)

class Tenant(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    # OSINT Licensing
    osint_enabled: bool = Field(default=False)
    osint_quota_max: int = Field(default=0)
    osint_quota_used: int = Field(default=0)
    osint_cost_per_search: float = Field(default=0.0)
    
    # OSINT BYOK (Bring Your Own Key)
    google_api_key: Optional[str] = Field(default=None)
    google_cse_cx: Optional[str] = Field(default=None)
    nuclei_api_key: Optional[str] = Field(default=None)
    hibp_api_key: Optional[str] = Field(default=None)

    # New OSINT API Keys (v1.15.0)
    hunter_api_key: Optional[str] = Field(default=None)  # Hunter.io email discovery
    github_token: Optional[str] = Field(default=None)     # GitHub API for social/code scanning
    twitter_bearer_token: Optional[str] = Field(default=None)  # Twitter/X API v2
    
    # Session Management
    session_timeout_minutes: int = Field(default=60) # Default 1 hour
    
    # Relationships
    users: List["User"] = Relationship(back_populates="tenant")
    targets: List["Target"] = Relationship(back_populates="tenant")
    
    # Authorized Users (M:N)
    allowed_users: List["User"] = Relationship(back_populates="allowed_tenants", link_model=UserTenantLink)
    webhooks: List["Webhook"] = Relationship(back_populates="tenant")

class Target(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    domain: str = Field(index=True, unique=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = Field(default=True)
    
    # Status Tracking
    scan_status: str = Field(default="idle") # idle, running, failed
    scan_progress: Optional[str] = Field(default=None) # e.g. "Running DNS Scanner..."
    
    # Archiving (for DNS cleanup)
    is_archived: bool = Field(default=False, index=True)
    archived_at: Optional[datetime] = None
    archived_reason: Optional[str] = None  # "dns_dead", "manual", "out_of_scope"
    
    # Tagging
    tags: List[str] = Field(default=[], sa_column=Column(JSONB))
    
    # Justification
    discovery_reason: Optional[str] = Field(default=None)
    
    # Visual Identity
    brand_logo_url: Optional[str] = Field(default=None)

    # Multi-Tenancy
    tenant_id: Optional[int] = Field(default=None, foreign_key="tenant.id")
    tenant: Optional[Tenant] = Relationship(back_populates="targets")
    
    # Relationships
    scan_results: List["ScanResult"] = Relationship(back_populates="target")
    module_states: List["ModuleState"] = Relationship(back_populates="target")
    http_traffic: List["HTTPTraffic"] = Relationship(back_populates="target")

class ModuleState(SQLModel, table=True):
    """
    Stores the state (hash) of the last run for a given module and target.
    Used to implement the 'Change Only' logic.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    module_name: str = Field(index=True)
    last_result_hash: str = Field(index=True)
    last_scanned_at: datetime = Field(default_factory=datetime.utcnow)
    
    target: Target = Relationship(back_populates="module_states")

class ScanResult(SQLModel, table=True):
    """
    Stores the actual data payload. Only created if hash changed.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    module_name: str = Field(index=True)
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Using SA Column for JSONB support
    data: dict = Field(default={}, sa_column=Column(JSONB))
    
    # Optional: Link to the hash that generated this result
    result_hash: str 
    
    # Execution Log
    log_content: Optional[str] = Field(default=None, sa_column=Column(String)) # Using String for Text behavior in some dialects, or import Text
 
    
    target: Target = Relationship(back_populates="scan_results")
    change_events: List["ChangeEvent"] = Relationship(back_populates="scan_result")

class ChangeEvent(SQLModel, table=True):
    """
    Represents a specific diff/change detected.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_result_id: int = Field(foreign_key="scanresult.id")
    event_type: str = Field(description="e.g. NEW_RECORD, DELETED_RECORD, CONTENT_CHANGE")
    description: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    scan_result: ScanResult = Relationship(back_populates="change_events")

class SystemConfig(SQLModel, table=True):
    """
    Stores runtime configuration settings.
    """
    key: str = Field(primary_key=True)
    value: str # Stored as string, parsed as needed (JSON, bool, int)
    description: Optional[str] = None

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    email: Optional[str] = Field(default=None) # Added in v1.3.0
    password_hash: str
    role: str = Field(default="auditor") # admin, tenant_admin, scanner, auditor
    is_active: bool = Field(default=True)
    last_login: Optional[datetime] = Field(default=None)
    
    # MFA Fields
    mfa_secret: Optional[str] = None
    mfa_enabled: bool = Field(default=False)
    
    # Password Policy
    force_password_change: bool = Field(default=False)

    # Multi-Tenancy
    tenant_id: Optional[int] = Field(default=None, foreign_key="tenant.id")
    tenant: Optional[Tenant] = Relationship(back_populates="users", sa_relationship_kwargs={"lazy": "selectin"})
    
    # Authorized Tenants (M:N)
    allowed_tenants: List[Tenant] = Relationship(back_populates="allowed_users", link_model=UserTenantLink, sa_relationship_kwargs={"lazy": "selectin"})

    # Changelog Tracking
    last_seen_changelog_id: Optional[int] = Field(default=0)

class ChangelogEntry(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    content: str  # HTML or Markdown
    version: str
    published_at: datetime = Field(default_factory=datetime.utcnow)

class Notification(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    text: str
    type: str = Field(default="info") # update, feature, maintenance, info
    color: str = Field(default="blue") # purple, emerald, amber, blue
    icon: str # SVG path or identifier
    created_at: datetime = Field(default_factory=datetime.utcnow)

class ScanSchedule(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    frequency: str = Field(default="daily") # daily, weekly
    cron_expression: Optional[str] = Field(default=None) # e.g. "0 0 * * *"
    next_run_at: datetime = Field(index=True)
    last_run_at: Optional[datetime] = Field(default=None)
    is_active: bool = Field(default=True)
    
    target: Target = Relationship(sa_relationship_kwargs={"lazy": "selectin"})

class Webhook(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: int = Field(foreign_key="tenant.id", index=True)
    url: str
    event_types: List[str] = Field(default=[], sa_column=Column(JSONB)) # ["scan_finished", "vuln_found", "new_asset"]
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    tenant: Tenant = Relationship(back_populates="webhooks")

class SecurityTrend(SQLModel, table=True):
    """
    Stores historical security scores for trend analysis.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: int = Field(foreign_key="tenant.id", index=True)
    score: int
    grade: str
    recorded_at: datetime = Field(default_factory=datetime.utcnow)

class HTTPTraffic(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    method: str
    url: str
    status_code: int
    request_headers: dict = Field(default={}, sa_column=Column(JSONB))
    response_headers: dict = Field(default={}, sa_column=Column(JSONB))
    response_body_snippet: Optional[str] = Field(default=None, sa_column=Column(Text))
    duration: float

    target: Target = Relationship(back_populates="http_traffic")


class ComplianceTrend(SQLModel, table=True):
    """
    Stores historical compliance scores for trend analysis by framework.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: int = Field(foreign_key="tenant.id", index=True)
    framework: str = Field(index=True)  # soc2, gdpr, pci_dss, hipaa, iso27001
    score: int
    grade: str
    passing_controls: int
    failing_controls: int
    recorded_at: datetime = Field(default_factory=datetime.utcnow, index=True)


class RemediationTask(SQLModel, table=True):
    """
    Tracks remediation tasks for compliance findings.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: int = Field(foreign_key="tenant.id", index=True)
    target_id: Optional[int] = Field(default=None, foreign_key="target.id", index=True)
    framework: str
    control_id: str
    finding_description: str
    title: str
    description: Optional[str] = None
    priority: str = Field(default="medium")  # critical, high, medium, low
    status: str = Field(default="open")  # open, in_progress, resolved, wont_fix
    due_date: Optional[datetime] = None
    sla_breached: bool = Field(default=False)
    assignee: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None


class ComplianceTargetStatus(SQLModel, table=True):
    """
    Stores per-target compliance status for each framework.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    framework: str = Field(index=True)
    score: int
    grade: str
    passing_controls: int
    failing_controls: int
    findings: List[dict] = Field(default=[], sa_column=Column(JSONB))
    last_assessed_at: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# Distributed Worker Models
# ============================================================================

class WorkerNode(SQLModel, table=True):
    """
    Represents a distributed worker node in the cluster.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    node_id: str = Field(unique=True, index=True)  # UUID + hostname hash
    hostname: str
    ip_address: str
    is_primary: bool = Field(default=False)  # Auto-registered main worker
    is_active: bool = Field(default=True)
    registered_at: datetime = Field(default_factory=datetime.utcnow)
    last_heartbeat: datetime = Field(default_factory=datetime.utcnow)
    max_concurrent_tasks: int = Field(default=4)
    max_network_mbps: float = Field(default=100.0)
    current_load: float = Field(default=0.0)  # 0-1 percentage
    current_tasks: int = Field(default=0)
    auth_token_hash: str  # Hashed registration token
    status: str = Field(default="pending")  # pending, active, offline, suspended, draining

    # Capabilities (scan types this worker can handle)
    capabilities: List[str] = Field(default=[], sa_column=Column(JSONB))

    # Metadata
    version: Optional[str] = None  # YADS version running on worker
    cpu_count: Optional[int] = None
    memory_mb: Optional[int] = None

    # Relationships
    tasks: List["WorkerTask"] = Relationship(back_populates="worker_node")


class WorkerTask(SQLModel, table=True):
    """
    Tracks individual tasks assigned to workers.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    task_id: str = Field(unique=True, index=True)  # Celery task ID
    worker_node_id: Optional[int] = Field(default=None, foreign_key="workernode.id", index=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    tenant_id: Optional[int] = Field(foreign_key="tenant.id", index=True)

    # Timing
    queued_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Status tracking
    status: str = Field(default="queued")  # queued, assigned, running, completed, failed, cancelled
    scan_types: List[str] = Field(default=[], sa_column=Column(JSONB))
    error_message: Optional[str] = None

    # Progress tracking
    progress_percent: int = Field(default=0)
    current_module: Optional[str] = None

    # Relationships
    worker_node: Optional[WorkerNode] = Relationship(back_populates="tasks")


class ResourceQuota(SQLModel, table=True):
    """
    Defines resource limits at global or per-tenant level.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: Optional[int] = Field(default=None, foreign_key="tenant.id", index=True)  # NULL = global

    # Concurrency limits
    max_concurrent_scans: int = Field(default=10)
    max_daily_scans: int = Field(default=1000)

    # Network limits
    max_network_throughput_mbps: float = Field(default=50.0)

    # Current usage (updated in real-time)
    current_concurrent_scans: int = Field(default=0)
    scans_today: int = Field(default=0)
    last_reset_date: Optional[datetime] = None  # For daily counter reset

    # Priority (higher = more priority in queue)
    priority: int = Field(default=5)  # 1-10 scale


# ============================================================================
# Security Audit Models
# ============================================================================

class SecurityAuditLog(SQLModel, table=True):
    """
    Stores security audit events for compliance and forensics.
    Aligned with MITRE ATT&CK framework.
    """
    id: Optional[int] = Field(default=None, primary_key=True)

    # Event identification
    event_type: str = Field(index=True)  # e.g., "login_success", "password_change"
    timestamp: datetime = Field(default_factory=datetime.utcnow, index=True)

    # Actor information (who performed the action)
    username: Optional[str] = Field(default=None, index=True)
    user_id: Optional[int] = Field(default=None, index=True)
    source_ip: Optional[str] = Field(default=None, index=True)
    user_agent: Optional[str] = Field(default=None)

    # Tenant context
    tenant_id: Optional[int] = Field(default=None, foreign_key="tenant.id", index=True)

    # Target information (for admin actions on other users)
    target_user: Optional[str] = Field(default=None, index=True)
    target_user_id: Optional[int] = Field(default=None, index=True)

    # Event outcome
    success: bool = Field(default=True, index=True)

    # Additional details (flexible JSON storage)
    details: dict = Field(default={}, sa_column=Column(JSONB))

    # MITRE ATT&CK mapping
    mitre_tactic_id: Optional[str] = Field(default=None, index=True)  # e.g., "TA0001"
    mitre_technique_id: Optional[str] = Field(default=None, index=True)  # e.g., "T1078"

