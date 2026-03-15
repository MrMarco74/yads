"""
Installation Reporting
======================
POST /api/installation        — anonymous opt-in telemetry from YADS instances
GET  /api/admin/installations — admin summary (total, per-version, timeline)
GET  /installations           — admin HTML dashboard page
"""
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlmodel import Session, select, func

from ..database import get_session
from ..models import InstallationReport

router = APIRouter()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ADMIN_TOKEN: Optional[str] = None  # populated from env in main.py

def _require_admin(request: Request) -> None:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = auth.split(" ", 1)[1]
    if not ADMIN_TOKEN or token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class InstallReportPayload(BaseModel):
    instance_uuid: str = Field(..., max_length=64)
    version: str = Field(..., max_length=50)
    submitted_at: Optional[str] = None


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@router.post("/api/installation")
async def ingest_installation(
    payload: InstallReportPayload,
    session: Session = Depends(get_session),
):
    """Accept anonymous installation report. Upsert by instance_uuid."""
    existing = session.exec(
        select(InstallationReport).where(InstallationReport.instance_uuid == payload.instance_uuid)
    ).first()

    now = datetime.now(timezone.utc)
    if existing:
        existing.version = payload.version
        existing.last_seen = now
        existing.report_count += 1
        session.add(existing)
    else:
        session.add(InstallationReport(
            instance_uuid=payload.instance_uuid,
            version=payload.version,
        ))
    session.commit()
    return {"ok": True}


@router.get("/api/admin/installations")
async def list_installations(
    request: Request,
    session: Session = Depends(get_session),
):
    _require_admin(request)
    rows = session.exec(
        select(InstallationReport).order_by(InstallationReport.last_seen.desc())
    ).all()

    # Version distribution
    version_dist: dict = {}
    for r in rows:
        version_dist[r.version] = version_dist.get(r.version, 0) + 1

    return JSONResponse({
        "total": len(rows),
        "version_distribution": [
            {"version": k, "count": v}
            for k, v in sorted(version_dist.items(), key=lambda x: -x[1])
        ],
        "installations": [
            {
                "instance_uuid": r.instance_uuid,
                "version": r.version,
                "first_seen": r.first_seen.isoformat(),
                "last_seen": r.last_seen.isoformat(),
                "report_count": r.report_count,
            }
            for r in rows
        ],
    })
