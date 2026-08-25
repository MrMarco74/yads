from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select
from typing import List, Optional, Annotated
from datetime import datetime
from yads.database import get_session
from yads.auth.deps import get_api_key, RequireScope
from yads.models import APIKey, Target, ScanResult
from yads.worker import celery_app

from pydantic import BaseModel

router = APIRouter(prefix="/api/v1", tags=["API v1"])

class DastScanRequest(BaseModel):
    target_url: str
    profile: str = "standard"

@router.post(
    "/dast/scan",
    responses={400: {"description": "Invalid target URL"}},
    dependencies=[Depends(RequireScope("scan_execute"))],
)
async def trigger_dast_scan(
    request: DastScanRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(get_api_key)]
):
    """
    Trigger a DAST scan for a target URL.
    Tenant context is automatically derived from the API Key.
    """
    target_url = request.target_url
    profile = request.profile
    # Clean up domain
    domain = target_url.replace("http://", "").replace("https://", "").split("/")[0].strip().lower()
    
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid target URL")

    # Find or Create Target
    target = session.exec(select(Target).where(Target.domain == domain, Target.tenant_id == api_key.tenant_id)).first()
    if not target:
        target = Target(domain=domain, tenant_id=api_key.tenant_id, discovery_reason="API v1 Request")
        session.add(target)
        session.commit()
        session.refresh(target)

    # Update Status
    target.scan_status = "queued"
    session.add(target)
    session.commit()

    # Determine scan types based on profile
    valid_types = ["dns_cleanup", "subdomain_scanner", "dns_scanner", "web_analyzer", "ssl_scanner", "crawler", "cve_scanner"]
    if profile == "full":
        scan_types = valid_types
    elif profile == "quick":
        scan_types = ["web_analyzer"]
    else: # standard
        scan_types = ["dns_scanner", "web_analyzer", "ssl_scanner"]

    # Dispatch to Celery
    celery_app.send_task("yads.worker.run_all_scans", args=[target.id, target.domain, scan_types, api_key.tenant_id])
    
    return {
        "status": "queued",
        "target": domain,
        "tenant_id": api_key.tenant_id,
        "profile": profile,
        "scan_types": scan_types
    }

# NOTE: GET /api/v1/findings now lives in v1_findings.py (Wave 3) — a
# filtered/paginated view over persisted SecurityFinding records. The old
# handler here dumped every raw ScanResult unfiltered (unusable at scale) and
# was removed to avoid a duplicate-route shadow.
