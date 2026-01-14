from datetime import datetime
from typing import Optional, List
from sqlmodel import SQLModel, Field, Relationship
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import Column, String


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
    
    # Tagging
    tags: List[str] = Field(default=[], sa_column=Column(JSONB))
    
    # Visual Identity
    brand_logo_url: Optional[str] = Field(default=None)

    # Multi-Tenancy
    tenant_id: Optional[int] = Field(default=None, foreign_key="tenant.id")
    tenant: Optional[Tenant] = Relationship(back_populates="targets")
    
    # Relationships
    scan_results: List["ScanResult"] = Relationship(back_populates="target")
    module_states: List["ModuleState"] = Relationship(back_populates="target")

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
