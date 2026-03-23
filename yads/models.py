from datetime import datetime, date
from typing import Optional, List
from sqlmodel import SQLModel, Field, Relationship
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import Column, String, Text


import sqlalchemy as sa
from yads.utils.crypto import encrypt_data, decrypt_data
from yads.config import settings

class EncryptedString(sa.TypeDecorator):
    """
    SQLAlchemy TypeDecorator that automatically encrypts/decrypts strings at rest.
    Requires settings.YADS_ENCRYPTION_KEY to be set.
    """
    impl = sa.Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None and value.strip():
            if not settings.YADS_ENCRYPTION_KEY:
                # If key is missing during dev/migration, don't crash but don't encrypt
                return value
            try:
                return encrypt_data(value, settings.YADS_ENCRYPTION_KEY)
            except Exception:
                return value
        return value

    def process_result_value(self, value, dialect):
        if value is not None and value.strip():
            if not settings.YADS_ENCRYPTION_KEY:
                return value
            try:
                return decrypt_data(value, settings.YADS_ENCRYPTION_KEY)
            except Exception:
                return value
        return value

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
    
    # OSINT BYOK (Bring Your Own Key) - NOW ENCRYPTED AT REST
    google_api_key: Optional[str] = Field(default=None, sa_column=Column(EncryptedString))
    google_cse_cx: Optional[str] = Field(default=None, sa_column=Column(EncryptedString))
    nuclei_api_key: Optional[str] = Field(default=None, sa_column=Column(EncryptedString))
    hibp_api_key: Optional[str] = Field(default=None, sa_column=Column(EncryptedString))

    # New OSINT API Keys (v1.15.0)
    hunter_api_key: Optional[str] = Field(default=None, sa_column=Column(EncryptedString))
    github_token: Optional[str] = Field(default=None, sa_column=Column(EncryptedString))
    twitter_bearer_token: Optional[str] = Field(default=None, sa_column=Column(EncryptedString))
    
    # Advanced OSINT Pivots (v1.16.0)
    shodan_api_key: Optional[str] = Field(default=None, sa_column=Column(EncryptedString))
    censys_api_key: Optional[str] = Field(default=None, sa_column=Column(EncryptedString))
    virustotal_api_key: Optional[str] = Field(default=None, sa_column=Column(EncryptedString))
    
    # Session Management
    session_timeout_minutes: int = Field(default=60) # Default 1 hour

    # LLM / AI Report Analysis (per-tenant)
    llm_provider: Optional[str] = Field(default=None)   # disabled|ollama|openai|anthropic|custom
    llm_api_url: Optional[str] = Field(default=None, sa_column=Column(EncryptedString))
    llm_api_key: Optional[str] = Field(default=None, sa_column=Column(EncryptedString))
    llm_model: Optional[str] = Field(default=None)

    # Finding SLA (days until due_date, BSI defaults)
    sla_critical: int = Field(default=7)
    sla_high: int = Field(default=30)
    sla_medium: int = Field(default=90)
    sla_low: int = Field(default=180)
    sla_info: Optional[int] = Field(default=None)  # None = no deadline

    # Report Branding Settings
    report_logo_url: Optional[str] = Field(default=None)  # URL or base64 data URI
    report_company_name: Optional[str] = Field(default=None)
    report_primary_color: str = Field(default="#3b82f6")  # Blue-500
    report_secondary_color: str = Field(default="#64748b")  # Slate-500
    report_header_text: Optional[str] = Field(default=None)  # Custom header text
    report_footer_text: Optional[str] = Field(default=None)  # Custom footer text

    # Relationships
    users: List["User"] = Relationship(back_populates="tenant")
    targets: List["Target"] = Relationship(back_populates="tenant")
    
    # Authorized Users (M:N)
    allowed_users: List["User"] = Relationship(back_populates="allowed_tenants", link_model=UserTenantLink)
    webhooks: List["Webhook"] = Relationship(back_populates="tenant")

    # Report Builder
    report_templates: List["ReportTemplate"] = Relationship(
        sa_relationship_kwargs={"foreign_keys": "[ReportTemplate.tenant_id]"}
    )
    generated_reports: List["GeneratedReport"] = Relationship(
        sa_relationship_kwargs={"foreign_keys": "[GeneratedReport.tenant_id]"}
    )

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

    # Scan Queue Priority (1=low, 5=normal, 9=high, 10=critical)
    scan_priority: int = Field(default=5)

    # Justification
    discovery_reason: Optional[str] = Field(default=None)

    # Discovery Session linkage
    discovery_session_id: Optional[int] = Field(default=None, foreign_key="discoverysession.id", index=True)
    parent_target_id: Optional[int] = Field(default=None)  # self-referential, no FK to avoid circular
    discovery_depth: int = Field(default=0)
    relevance_score: Optional[float] = Field(default=None)
    discovery_signals: List[str] = Field(default=[], sa_column=Column(JSONB))

    # Visual Identity
    brand_logo_url: Optional[str] = Field(default=None)

    # Multi-Tenancy
    tenant_id: Optional[int] = Field(default=None, foreign_key="tenant.id")
    tenant: Optional[Tenant] = Relationship(back_populates="targets")

    # Relationships
    scan_results: List["ScanResult"] = Relationship(back_populates="target")
    module_states: List["ModuleState"] = Relationship(back_populates="target")
    http_traffic: List["HTTPTraffic"] = Relationship(back_populates="target")
    osint_records: List["OSINTIntelligence"] = Relationship(back_populates="target")


class DiscoverySession(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: Optional[int] = Field(default=None, foreign_key="tenant.id", index=True)
    created_by: Optional[int] = Field(default=None, foreign_key="user.id")
    name: str = Field(index=True)

    # Initial seed domains
    seed_domains: List[str] = Field(default=[], sa_column=Column(JSONB))

    # Configuration
    max_depth: int = Field(default=3)
    relevance_threshold: float = Field(default=0.7)
    max_targets: int = Field(default=500)
    include_typosquats: bool = Field(default=False)
    passive_hunting: bool = Field(default=False)
    web_scraping: bool = Field(default=False)
    allowed_tld_filter: List[str] = Field(default=[], sa_column=Column(JSONB))

    # Status: pending / running / paused / completed / failed / stopped
    status: str = Field(default="pending")
    started_at: Optional[datetime] = Field(default=None)
    finished_at: Optional[datetime] = Field(default=None)

    # Live stats
    total_discovered: int = Field(default=0)
    total_accepted: int = Field(default=0)
    total_rejected: int = Field(default=0)
    current_depth: int = Field(default=0)

    created_at: datetime = Field(default_factory=datetime.utcnow)


class DiscoveryCandidate(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    session_id: int = Field(foreign_key="discoverysession.id", index=True)
    source_target_id: Optional[int] = Field(default=None, foreign_key="target.id")
    domain: str = Field(index=True)
    source_scanner: str  # "dns_scanner", "ssl_scanner", etc.
    depth: int = Field(default=0)
    relevance_score: float = Field(default=0.0)
    matching_signals: List[str] = Field(default=[], sa_column=Column(JSONB))
    # status: pending / accepted / rejected / duplicate
    status: str = Field(default="pending")
    rejection_reason: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class DiscoveryDomainBlocklist(SQLModel, table=True):
    """
    Tenant-wide blocklist of domain patterns for Discovery sessions.
    Pattern format: "*.example.com" (all subdomains) or "example.com" (exact).
    Candidates matching a pattern are silently skipped — never added to Target list.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: Optional[int] = Field(default=None, foreign_key="tenant.id", index=True)
    pattern: str = Field(index=True)      # e.g. "*.example.com"
    created_by: Optional[int] = Field(default=None, foreign_key="user.id")
    note: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=datetime.utcnow)


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

class OSINTIntelligence(SQLModel, table=True):
    """
    Structured intelligence data from OSINT modules like breached credentials,
    historical WHOIS, or leaked secrets.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)

    # E.g. 'leaked_credentials', 'dns_history_scanner'
    module_name: str = Field(index=True)

    # E.g. 'breach_record', 'whois_archive', 'github_leak'
    data_type: str = Field(index=True)

    # The actual OSINT payload
    data_json: dict = Field(default={}, sa_column=Column(JSONB))

    # severity: info, low, medium, high, critical
    severity: str = Field(default="info", index=True)

    timestamp: datetime = Field(default_factory=datetime.utcnow, index=True)

    # Relationships
    target: Target = Relationship(back_populates="osint_records")

class AIAnalysisResult(SQLModel, table=True):
    """Stores AI-generated risk assessments per tenant."""
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: Optional[int] = Field(default=None, foreign_key="tenant.id", index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    risk_rating: str = Field(default="UNKNOWN")
    risk_score: int = Field(default=0)
    executive_summary: str = Field(default="")
    key_findings: str = Field(default="[]")       # JSON array
    recommendations: str = Field(default="[]")    # JSON array
    llm_provider: Optional[str] = Field(default=None)
    llm_model: Optional[str] = Field(default=None)


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
    pending_mfa_secret: Optional[str] = None  # Temp secret during MFA enrollment (server-side only)
    
    # Password Policy
    force_password_change: bool = Field(default=False)

    # Multi-Tenancy
    tenant_id: Optional[int] = Field(default=None, foreign_key="tenant.id")
    tenant: Optional[Tenant] = Relationship(back_populates="users", sa_relationship_kwargs={"lazy": "selectin"})
    
    # Authorized Tenants (M:N)
    allowed_tenants: List[Tenant] = Relationship(back_populates="allowed_users", link_model=UserTenantLink, sa_relationship_kwargs={"lazy": "selectin"})

    # UI Language preference (EN/DE)
    language: str = Field(default="en")

    # Changelog Tracking
    last_seen_changelog_id: Optional[int] = Field(default=0)

    # OIDC/External Auth
    auth_mode: str = Field(default="local")  # "local" oder "oidc"
    oidc_sub: Optional[str] = Field(default=None, index=True)  # Keycloak Subject-ID
    oidc_tenant: Optional[str] = Field(default=None)  # Keycloak Realm/Tenant-Name

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

    # Tenant Assignment (empty = all tenants, list = specific tenants only)
    assigned_tenant_ids: List[int] = Field(default=[], sa_column=Column(JSONB))

    # Worker-specific limits (can override defaults)
    max_daily_scans: Optional[int] = Field(default=None)  # NULL = no limit
    description: Optional[str] = Field(default=None)  # Human-readable description

    # Metadata
    version: Optional[str] = None  # YADS version running on worker
    cpu_count: Optional[int] = None
    memory_mb: Optional[int] = None
    requested_action: Optional[str] = Field(default=None)  # stop, restart

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

    # DORA EU Art. 10 Hash-Chain (Tamper-Proof Logging)
    prev_entry_hash: Optional[str] = Field(default=None)  # Hash des vorherigen Eintrags
    entry_hash: Optional[str] = Field(default=None)       # SHA256(content + prev_hash)


def compute_audit_hash(entry: "SecurityAuditLog", prev_hash: Optional[str] = None) -> str:
    """
    Berechnet SHA256-Hash eines Audit-Log-Eintrags.
    Bindet prev_hash ein für Hash-Chain-Integrität (DORA EU Art. 10).
    """
    import hashlib, json
    content = {
        "action": entry.event_type,
        "user_id": entry.user_id,
        "timestamp": entry.timestamp.isoformat() if entry.timestamp else "",
        "details": entry.details,
        "prev_hash": prev_hash or "GENESIS",
    }
    return hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()


# ============================================================================
# Report Builder Models
# ============================================================================

class ReportTemplate(SQLModel, table=True):
    """
    Stores reusable report templates with markdown content and variable placeholders.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: Optional[int] = Field(default=None, foreign_key="tenant.id", index=True)  # NULL = system template

    name: str = Field(index=True)
    description: Optional[str] = None

    # Template content in Markdown with Jinja2-style placeholders
    # e.g., {{ target.domain }}, {{ scan_results.dns }}, {{ tenant.report_company_name }}
    markdown_content: str = Field(sa_column=Column(Text))

    # Template metadata
    category: str = Field(default="custom")  # executive, technical, compliance, custom
    is_default: bool = Field(default=False)  # System default template
    is_public: bool = Field(default=False)  # Visible to all tenants (system templates)

    # Available data sections that can be included
    # e.g., ["summary", "dns", "ssl", "vulnerabilities", "compliance", "screenshots"]
    available_sections: List[str] = Field(default=[], sa_column=Column(JSONB))

    # Custom CSS for PDF styling (optional)
    custom_css: Optional[str] = Field(default=None, sa_column=Column(Text))

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[int] = Field(default=None, foreign_key="user.id")


class GeneratedReport(SQLModel, table=True):
    """
    Stores generated reports (both preview and final exports).
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: int = Field(foreign_key="tenant.id", index=True)
    template_id: Optional[int] = Field(default=None, foreign_key="reporttemplate.id")

    # Report metadata
    title: str
    description: Optional[str] = None

    # Target scope - can be single target or multiple
    target_ids: List[int] = Field(default=[], sa_column=Column(JSONB))

    # Content storage
    markdown_content: str = Field(sa_column=Column(Text))  # Rendered markdown (with data filled in)
    html_content: Optional[str] = Field(default=None, sa_column=Column(Text))  # Rendered HTML

    # PDF storage (base64 or file path)
    pdf_data: Optional[str] = Field(default=None, sa_column=Column(Text))  # Base64 encoded PDF
    pdf_file_path: Optional[str] = Field(default=None)  # Alternative: file system path

    # Status tracking
    status: str = Field(default="draft")  # draft, generating, completed, failed, archived
    error_message: Optional[str] = None

    # Report configuration snapshot (branding at time of generation)
    branding_snapshot: dict = Field(default={}, sa_column=Column(JSONB))

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    generated_at: Optional[datetime] = None

    # Creator
    created_by: Optional[int] = Field(default=None, foreign_key="user.id")


class APIKey(SQLModel, table=True):
    """
    Secure API keys for machine-to-machine communication (e.g., LLMGui -> YADS).
    Keys are stored as hashes (SHA-256).
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: int = Field(foreign_key="tenant.id", index=True)

    name: str = Field(description="Friendly name for the key (e.g., 'LLMGui-Laptop')")
    key_prefix: str = Field(index=True, description="First 6-8 characters of the key for display/lookup")
    key_hash: str = Field(index=True, description="SHA-256 hash of the full key")

    scopes: List[str] = Field(default=["read"], sa_column=Column(JSONB), description="List of authorized scopes")

    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    is_active: bool = Field(default=True)

    # Relationships
    tenant: Tenant = Relationship(sa_relationship_kwargs={"lazy": "selectin"})


class TenantModuleConfig(SQLModel, table=True):
    """Per-tenant module enable/disable override. Absent row = enabled (default)."""
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: int = Field(foreign_key="tenant.id", index=True)
    module_name: str = Field(index=True)
    enabled: bool = Field(default=True)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    updated_by: Optional[int] = Field(default=None, foreign_key="user.id")


class TenantScanConfig(SQLModel, table=True):
    """Per-tenant automated scan configuration."""
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: int = Field(foreign_key="tenant.id", unique=True, index=True)

    # Master switch
    auto_scan_enabled: bool = Field(default=False)

    # Frequency: "daily", "weekly", "monthly" — or use cron_expression
    frequency: str = Field(default="weekly")
    cron_expression: Optional[str] = Field(default=None)

    # Scan types to run automatically
    scan_types: List[str] = Field(
        default=["dns_scanner", "ssl_scanner", "web_analyzer"],
        sa_column=Column(JSONB)
    )

    # Throttling
    max_targets_per_run: int = Field(default=10)    # max queued per scheduler tick
    max_concurrent_scans: int = Field(default=3)    # max active at once for this tenant

    # Optional time window (UTC, "HH:MM" strings). NULL = always allowed.
    scan_window_start: Optional[str] = Field(default=None)
    scan_window_end: Optional[str] = Field(default=None)

    # Scheduler tracking
    last_auto_run_at: Optional[datetime] = Field(default=None)
    next_auto_run_at: Optional[datetime] = Field(default=None, index=True)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class InstalledModule(SQLModel, table=True):
    """Dynamically installed scanner modules (uploaded as ZIP packages by admin)."""
    id: Optional[int] = Field(default=None, primary_key=True)
    module_name: str = Field(unique=True, index=True)
    label: str
    label_de: str = Field(default="")
    category: str = Field(default="active")
    version: str = Field(default="1.0.0")
    author: str = Field(default="")
    description: str = Field(default="")
    module_path: str  # "yads.modules.custom.xxx:ClassName"
    requires_http: bool = Field(default=False)
    requires_https: bool = Field(default=False)
    default_on: bool = Field(default=False)
    finding_module: bool = Field(default=True)
    extractor: str = Field(default="generic")
    installed_at: datetime = Field(default_factory=datetime.utcnow)
    installed_by: Optional[int] = Field(default=None, foreign_key="user.id")
    is_active: bool = Field(default=True)
    passive: bool = Field(default=True)  # True = read-only/safe, False = active/intrusive
    setup_log: Optional[str] = Field(default=None, sa_column=Column(String))
    # Module signing & integrity
    signature: Optional[str] = Field(default=None, sa_column=Column(String))
    # ^ Ed25519 signature over SHA-256(zip_bytes) supplied at upload time (audit trail)
    file_hash: Optional[str] = Field(default=None, sa_column=Column(String))
    # ^ SHA-256 of the installed .py file; re-verified on every startup


class ScanProfile(SQLModel, table=True):
    """
    Saved scan configuration profile — a named set of scanner modules + settings.
    Allows users to save commonly used scan configurations and apply them quickly.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: Optional[int] = Field(default=None, foreign_key="tenant.id", index=True)
    created_by: Optional[int] = Field(default=None, foreign_key="user.id")

    name: str = Field(index=True)
    description: Optional[str] = Field(default=None)

    # List of module names to enable in this profile
    scan_types: List[str] = Field(default=[], sa_column=Column(JSONB))

    # Metadata
    is_default: bool = Field(default=False)  # Shown as default selection for tenant
    is_public: bool = Field(default=False)   # Visible to all tenant users (not just creator)
    icon: Optional[str] = Field(default=None)  # emoji or icon name
    color: str = Field(default="blue")       # UI accent color

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class IntegrationConfig(SQLModel, table=True):
    """
    Stores configuration for external integrations (Jira, GitHub Issues, SIEM, etc.).
    One row per integration type per tenant.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: int = Field(foreign_key="tenant.id", index=True)

    integration_type: str = Field(index=True)  # "jira", "github", "siem_syslog", "siem_http", "slack"

    # Connection details (encrypted at rest ideally, stored as JSONB for flexibility)
    config: dict = Field(default={}, sa_column=Column(JSONB))

    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[int] = Field(default=None, foreign_key="user.id")


class SystemAlertLog(SQLModel, table=True):
    """
    Persistent log of health-watcher alerts.
    One open row per (check_name, severity) pair — resolved_at is set when the
    condition clears.  New rows are only created after the previous entry for the
    same check was resolved, preventing duplicate spam.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    check_name: str = Field(index=True)          # e.g. "worker_heartbeat"
    severity: str                                 # "warning" | "error"
    message: str
    detail: Optional[str] = Field(default=None)  # JSON context (node_id, domain, …)
    fired_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    resolved_at: Optional[datetime] = Field(default=None)
    notified: bool = Field(default=False)         # webhook already sent


class SecurityFinding(SQLModel, table=True):
    """
    Persistent record for each unique security finding (domain|module|issue).
    Created on first detection, updated on every subsequent scan.
    """
    id: Optional[int] = Field(default=None, primary_key=True)

    # Identity
    yf_id: str = Field(index=True, unique=True)          # e.g. "YF-000042"
    finding_hash: str = Field(index=True, unique=True)   # SHA256[:16] of domain|module|issue
    tenant_id: Optional[int] = Field(default=None, foreign_key="tenant.id", index=True)
    target_id: Optional[int] = Field(default=None, foreign_key="target.id", index=True)
    domain: str = Field(index=True)
    module: str
    issue: str
    severity: str  # critical | high | medium | low | info

    # Lifecycle
    first_found: datetime = Field(default_factory=datetime.utcnow, index=True)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    closing_date: Optional[datetime] = Field(default=None)
    due_date: Optional[date] = Field(default=None)

    # Triage
    status: str = Field(default="open", index=True)  # open | acknowledged | false_positive | fixed
    status_note: Optional[str] = Field(default=None)
    status_updated_at: Optional[datetime] = Field(default=None)
    status_updated_by: Optional[str] = Field(default=None)
    assigned_to: Optional[str] = Field(default=None)
    ticket_ref: Optional[str] = Field(default=None)

    # Recurrence tracking
    reopened_count: int = Field(default=0)
