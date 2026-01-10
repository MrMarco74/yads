from datetime import datetime
from typing import Optional, List
from sqlmodel import SQLModel, Field, Relationship
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import Column, String

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
