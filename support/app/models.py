from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


class ReportCategory(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True)
    color: str = Field(default="blue")   # blue|green|red|yellow|purple|orange|gray
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BugReport(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    report_id: str = Field(unique=True, index=True)  # "YAD-2026-00042"
    customer_id: str = Field(index=True)
    customer_name: str
    tenant_name: str
    yads_version: str
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = Field(default="new")  # "new" | "open" | "resolved"
    topic: str = Field(default="")  # short category, e.g. "scanner", "ui", "performance"
    description: str = Field(default="")  # first 300 chars of description field
    full_report: str  # full decrypted JSON as string
    category_id: Optional[int] = Field(default=None, foreign_key="reportcategory.id")


class BugReportMessage(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    report_id: str = Field(index=True)        # matches BugReport.report_id
    sender: str                                # "support" | "customer"
    author_name: str = Field(default="")
    text: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_read_by_customer: bool = Field(default=False)
    is_read_by_support: bool = Field(default=False)


class InstallationReport(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    instance_uuid: str = Field(unique=True, index=True)
    version: str
    install_type: str = Field(default="unknown")  # "installer" | "web_wizard" | "unknown"
    customer_id: Optional[str] = Field(default=None, index=True)  # matches CustomerKey.customer_id
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    report_count: int = Field(default=1)


class ContactRequest(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    contact_id: str = Field(unique=True, index=True)   # "CON-2026-00001"
    name: str
    email: str
    company: str = Field(default="")
    topic: str = Field(default="general")              # demo | support | sales | general
    message: str
    client_ip: str = Field(default="")
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = Field(default="new")                 # offen | in_arbeit | potenzial | kunde | spam
    notes: str = Field(default="")                     # internal support notes


class CustomerKey(SQLModel, table=True):
    customer_id: str = Field(primary_key=True)
    customer_name: str
    public_key_b64: str  # Ed25519 raw public key, base64
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_sync: Optional[datetime] = None
    is_eos: bool = Field(default=False)          # End of Support — customer deleted/terminated
    eos_since: Optional[datetime] = None
