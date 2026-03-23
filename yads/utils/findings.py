import hashlib
from typing import Set, Optional
from sqlmodel import Session, select
from yads.models import SecurityFinding

def get_finding_hash(domain: str, module: str, issue: str) -> str:
    """
    Standardized deterministic hash for a finding, used as status map key.
    Must match the logic in security_findings.py.
    """
    raw = f"{domain}|{module}|{issue}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

class FindingStatusFilter:
    """
    Helper to efficiently filter out non-open findings (Fixed or False Positive)
    for a given tenant context.
    """
    def __init__(self, session: Session, tenant_id: Optional[int]):
        self.ignored_hashes: Set[str] = set()
        
        # Fetch all findings that are NOT open for this tenant
        statement = select(SecurityFinding.finding_hash).where(
            SecurityFinding.status.in_(["fixed", "false_positive"])
        )
        if tenant_id:
            statement = statement.where(SecurityFinding.tenant_id == tenant_id)
        else:
            statement = statement.where(SecurityFinding.tenant_id == None)
            
        results = session.exec(statement).all()
        self.ignored_hashes = set(results)

    def is_ignored(self, domain: str, module: str, issue: str) -> bool:
        """Returns True if the finding should be filtered out."""
        fhash = get_finding_hash(domain, module, issue)
        return fhash in self.ignored_hashes
