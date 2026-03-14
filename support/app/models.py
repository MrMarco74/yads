from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


class BugReport(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    report_id: str = Field(unique=True, index=True)  # "YAD-2026-00042"
    customer_id: str = Field(index=True)
    customer_name: str
    tenant_name: str
    yads_version: str
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = Field(default="new")  # "new" | "open" | "resolved"
    description: str = Field(default="")  # first 300 chars of description field
    full_report: str  # full decrypted JSON as string


class CustomerKey(SQLModel, table=True):
    customer_id: str = Field(primary_key=True)
    customer_name: str
    public_key_b64: str  # Ed25519 raw public key, base64
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_sync: Optional[datetime] = None
