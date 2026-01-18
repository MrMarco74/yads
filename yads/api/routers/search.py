
from fastapi import APIRouter, Depends, Request
from sqlmodel import Session, select, or_, text
from yads.database import get_session
from yads.models import Target, ScanResult, User
from yads.auth.deps import get_current_user_html
from yads.config import settings

router = APIRouter(prefix="/api/search", tags=["search"])

@router.get("")
async def global_search(
    q: str, 
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html)
):
    if not q or len(q) < 2:
        return {"targets": [], "findings": []}
        
    query = q.lower().strip()
    
    # 1. Search Targets (Domain match)
    targets_stmt = select(Target).where(
        Target.tenant_id == user.tenant_id,
        Target.domain.contains(query)
    ).limit(10)
    
    targets = session.exec(targets_stmt).all()
    target_results = [{"id": t.id, "domain": t.domain} for t in targets]
    
    # 2. Search Findings (Deep Search in JSONB)
    # This is heavy, limit to key modules
    # We use text-based search on the JSON column or specific keys
    
    findings = []
    
    # Postgres specific JSONB search would be better, but we strive for generic SQLModel or strings
    # Simple formatting: CAST(data AS TEXT) ILIKE %query%
    
    # modules to search
    modules = ["web_analyzer", "cve_scanner", "nuclei_scanner"]
    
    # We restrict to targets of this tenant
    # Subquery for target IDs?
    
    # Optimization: Only search recent results? Or search all?
    # Let's limit to 20 matches
    
    sql = text("""
        SELECT s.id, s.target_id, s.module_name, t.domain
        FROM scanresult s
        JOIN target t ON s.target_id = t.id
        WHERE t.tenant_id = :tenant_id
        AND s.module_name IN ('web_analyzer', 'cve_scanner', 'nuclei_scanner')
        AND CAST(s.data AS TEXT) ILIKE :query
        ORDER BY s.scanned_at DESC
        LIMIT 20
    """)
    
    raw_findings = session.exec(sql, params={"tenant_id": user.tenant_id, "query": f"%{query}%"}).all()
    
    for f in raw_findings:
        findings.append({
            "target_id": f[1],
            "module": f[2],
            "target": f[3]
        })
        
    return {
        "targets": target_results,
        "findings": findings
    }
