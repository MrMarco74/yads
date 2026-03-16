"""
Installation Reporting & Activation
=====================================
POST /api/installation              — opt-in telemetry (CE) / activation (business)
POST /api/admin/activate-offline    — manually ingest an offline activation request code
GET  /api/admin/installations       — admin summary (total, per-version, timeline)
GET  /installations                 — admin HTML dashboard page
"""
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlmodel import Session, select, func

from ..database import get_session
from ..models import ActivationRequest, InstallationReport

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
    install_type: Optional[str] = Field(default="unknown", max_length=32)
    customer_id: Optional[str] = Field(default=None, max_length=64)


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

    install_type = (payload.install_type or "unknown").strip() or "unknown"
    customer_id = (payload.customer_id or "").strip() or None
    now = datetime.now(timezone.utc)
    if existing:
        existing.version = payload.version
        existing.last_seen = now
        existing.report_count += 1
        if existing.install_type == "unknown" and install_type != "unknown":
            existing.install_type = install_type
        if not existing.customer_id and customer_id:
            existing.customer_id = customer_id
        session.add(existing)
    else:
        session.add(InstallationReport(
            instance_uuid=payload.instance_uuid,
            version=payload.version,
            install_type=install_type,
            customer_id=customer_id,
        ))
    session.commit()

    # Create ActivationRequest record with status="pending" if none exists
    existing_ar = session.exec(
        select(ActivationRequest).where(ActivationRequest.instance_uuid == payload.instance_uuid)
    ).first()
    if not existing_ar:
        session.add(ActivationRequest(
            instance_uuid=payload.instance_uuid,
            customer_id=customer_id,
            request_code="",  # no request code for direct telemetry reports
            status="pending",
        ))
        session.commit()

    return {"ok": True}


class OfflineActivationRequest(BaseModel):
    code: str  # base64url-encoded JSON payload from the installer


@router.post("/api/admin/activate-offline")
async def activate_offline(
    req: OfflineActivationRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    """
    Manually ingest an offline activation request code sent by the customer.
    Decodes the base64url payload and upserts an InstallationReport.
    Requires admin token.
    """
    import base64, json
    _require_admin(request)

    # Decode the activation code (base64url, no padding needed)
    try:
        padded = req.code + '=' * ((4 - len(req.code) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid activation code: {exc}")

    required = {"instance_uuid", "version"}
    if not required.issubset(payload.keys()):
        raise HTTPException(status_code=400, detail="Activation code missing required fields.")

    install_type = (payload.get("install_type") or "installer").strip()
    customer_id = (payload.get("customer_id") or "").strip() or None
    now = datetime.now(timezone.utc)

    existing = session.exec(
        select(InstallationReport).where(
            InstallationReport.instance_uuid == payload["instance_uuid"]
        )
    ).first()

    if existing:
        existing.version = payload["version"]
        existing.last_seen = now
        existing.report_count += 1
        if existing.install_type == "unknown" and install_type != "unknown":
            existing.install_type = install_type
        if not existing.customer_id and customer_id:
            existing.customer_id = customer_id
        session.add(existing)
    else:
        session.add(InstallationReport(
            instance_uuid=payload["instance_uuid"],
            version=payload["version"],
            install_type=install_type,
            customer_id=customer_id,
        ))
    session.commit()

    # Also create an ActivationRequest with status="approved" (admin manually ingested it)
    existing_ar = session.exec(
        select(ActivationRequest).where(
            ActivationRequest.instance_uuid == payload["instance_uuid"]
        )
    ).first()
    if not existing_ar:
        session.add(ActivationRequest(
            instance_uuid=payload["instance_uuid"],
            customer_id=customer_id,
            request_code=req.code,
            status="approved",
            resolved_at=now,
        ))
        session.commit()

    return {"ok": True, "instance_uuid": payload["instance_uuid"]}


@router.get("/api/admin/installations")
async def list_installations(
    request: Request,
    session: Session = Depends(get_session),
):
    _require_admin(request)
    rows = session.exec(
        select(InstallationReport).order_by(InstallationReport.last_seen.desc())
    ).all()

    # Build customer_id → customer_name lookup
    from ..models import CustomerKey
    cust_ids = {r.customer_id for r in rows if r.customer_id}
    cust_map: dict = {}
    for cid in cust_ids:
        ck = session.get(CustomerKey, cid)
        if ck:
            cust_map[cid] = ck.customer_name

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
                "install_type": r.install_type,
                "customer_id": r.customer_id,
                "customer_name": cust_map.get(r.customer_id) if r.customer_id else None,
                "first_seen": r.first_seen.isoformat(),
                "last_seen": r.last_seen.isoformat(),
                "report_count": r.report_count,
            }
            for r in rows
        ],
    })


# ---------------------------------------------------------------------------
# Activation Request endpoints
# ---------------------------------------------------------------------------

class ActivationRespondPayload(BaseModel):
    response_code: str


@router.post("/api/admin/activation-requests/{instance_uuid}/respond")
async def respond_to_activation_request(
    instance_uuid: str,
    body: ActivationRespondPayload,
    request: Request,
    session: Session = Depends(get_session),
):
    """
    Store a signed activation response code for a pending ActivationRequest.
    Requires admin token.
    """
    _require_admin(request)

    ar = session.exec(
        select(ActivationRequest).where(ActivationRequest.instance_uuid == instance_uuid)
    ).first()
    if not ar:
        raise HTTPException(status_code=404, detail="Activation request not found.")

    ar.response_code = body.response_code
    ar.status = "approved"
    ar.resolved_at = datetime.now(timezone.utc)
    session.add(ar)
    session.commit()
    return {"ok": True}


@router.get("/api/admin/activation-requests")
async def list_activation_requests(
    request: Request,
    session: Session = Depends(get_session),
):
    """
    Return all ActivationRequests ordered by received_at descending.
    Includes customer_name via CustomerKey join.
    Requires admin token.
    """
    _require_admin(request)

    from ..models import CustomerKey

    rows = session.exec(
        select(ActivationRequest).order_by(ActivationRequest.received_at.desc())
    ).all()

    # Build customer_id → customer_name lookup
    cust_ids = {r.customer_id for r in rows if r.customer_id}
    cust_map: dict = {}
    for cid in cust_ids:
        ck = session.get(CustomerKey, cid)
        if ck:
            cust_map[cid] = ck.customer_name

    return JSONResponse([
        {
            "id": r.id,
            "instance_uuid": r.instance_uuid,
            "customer_id": r.customer_id,
            "customer_name": cust_map.get(r.customer_id) if r.customer_id else None,
            "status": r.status,
            "has_response_code": bool(r.response_code),
            "received_at": r.received_at.isoformat(),
            "resolved_at": r.resolved_at.isoformat() if r.resolved_at else None,
        }
        for r in rows
    ])
