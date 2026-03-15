"""
Bidirectional messaging between customers (YADS) and support staff.

Customer endpoints (/api/customer/…):
  Ed25519 auth — customer signs canonical JSON with their report-signing private key.
  Support portal verifies using the stored CustomerKey.public_key_b64.

Admin endpoints (/api/admin/reports/{id}/messages):
  Bearer token + IP allowlist (same as admin_keys.py).
"""

import base64
import json
import time
from datetime import datetime, timezone
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlmodel import Session, col, select

from app.database import get_session
from app.models import BugReport, BugReportMessage, CustomerKey
from app.routers.admin_keys import _check_bearer, _check_ip

router = APIRouter()

_MAX_MSG_LEN = 4000
_TS_WINDOW = 90  # seconds


# ---------------------------------------------------------------------------
# Customer auth helper
# ---------------------------------------------------------------------------

def _verify_customer(
    report_id: Optional[str],
    customer_id: str,
    timestamp_str: str,
    signature_b64: str,
    session: Session,
) -> CustomerKey:
    """
    Verify an Ed25519-signed customer request.
    Signed payload: json.dumps({"customer_id": …, "report_id": …, "timestamp": …}, sort_keys=True)
    For list endpoint (no report_id) omit report_id from the payload.
    """
    try:
        ts = float(timestamp_str)
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="X-Timestamp must be a unix timestamp.")
    if abs(time.time() - ts) > _TS_WINDOW:
        raise HTTPException(status_code=401, detail="Timestamp expired.")

    key_row = session.exec(
        select(CustomerKey).where(CustomerKey.customer_id == customer_id)
    ).first()
    if not key_row or not key_row.public_key_b64:
        raise HTTPException(status_code=403, detail="Unknown customer.")
    if key_row.is_eos:
        raise HTTPException(status_code=403, detail="Customer is marked End-of-Support.")

    payload: dict = {"customer_id": customer_id, "timestamp": ts}
    if report_id is not None:
        payload["report_id"] = report_id

    canonical = json.dumps(payload, sort_keys=True).encode()

    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(key_row.public_key_b64))
        pub.verify(base64.b64decode(signature_b64), canonical)
    except InvalidSignature:
        raise HTTPException(status_code=403, detail="Signature verification failed.")
    except Exception as e:
        raise HTTPException(status_code=403, detail=f"Auth error: {e}")

    return key_row


def _assert_report_owner(report_id: str, customer_id: str, session: Session) -> BugReport:
    report = session.exec(
        select(BugReport).where(BugReport.report_id == report_id)
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")
    if report.customer_id != customer_id:
        raise HTTPException(status_code=403, detail="Access denied.")
    return report


# ---------------------------------------------------------------------------
# Customer endpoints
# ---------------------------------------------------------------------------

@router.get("/api/customer/reports")
async def customer_list_reports(
    request: Request,
    x_customer_id: Optional[str] = Header(default=None, alias="X-Customer-Id"),
    x_timestamp: Optional[str] = Header(default=None, alias="X-Timestamp"),
    x_signature: Optional[str] = Header(default=None, alias="X-Signature"),
    session: Session = Depends(get_session),
):
    """List all bug reports for this customer with unread message counts."""
    if not x_customer_id or not x_timestamp or not x_signature:
        raise HTTPException(status_code=401, detail="Missing auth headers.")

    _verify_customer(None, x_customer_id, x_timestamp, x_signature, session)

    reports = session.exec(
        select(BugReport)
        .where(BugReport.customer_id == x_customer_id)
        .order_by(col(BugReport.submitted_at).desc())
    ).all()

    # Unread = support messages not yet read by customer
    unread_counts: dict[str, int] = {}
    for r in reports:
        unread_counts[r.report_id] = session.exec(
            select(BugReportMessage).where(
                BugReportMessage.report_id == r.report_id,
                BugReportMessage.sender == "support",
                BugReportMessage.is_read_by_customer == False,
            )
        ).all().__len__()

    return {
        "reports": [
            {
                "report_id": r.report_id,
                "topic": r.topic,
                "description": r.description,
                "status": r.status,
                "yads_version": r.yads_version,
                "submitted_at": r.submitted_at.isoformat(),
                "unread": unread_counts.get(r.report_id, 0),
            }
            for r in reports
        ]
    }


@router.get("/api/customer/reports/{report_id}/messages")
async def customer_get_messages(
    report_id: str,
    x_customer_id: Optional[str] = Header(default=None, alias="X-Customer-Id"),
    x_timestamp: Optional[str] = Header(default=None, alias="X-Timestamp"),
    x_signature: Optional[str] = Header(default=None, alias="X-Signature"),
    session: Session = Depends(get_session),
):
    """Return message thread for one report and mark support messages as read."""
    if not x_customer_id or not x_timestamp or not x_signature:
        raise HTTPException(status_code=401, detail="Missing auth headers.")

    _verify_customer(report_id, x_customer_id, x_timestamp, x_signature, session)
    report = _assert_report_owner(report_id, x_customer_id, session)

    msgs = session.exec(
        select(BugReportMessage)
        .where(BugReportMessage.report_id == report_id)
        .order_by(col(BugReportMessage.created_at).asc())
    ).all()

    # Mark all support messages as read by customer
    for m in msgs:
        if m.sender == "support" and not m.is_read_by_customer:
            m.is_read_by_customer = True
            session.add(m)
    session.commit()

    return {
        "report_id": report_id,
        "status": report.status,
        "topic": report.topic,
        "messages": [
            {
                "id": m.id,
                "sender": m.sender,
                "author_name": m.author_name,
                "text": m.text,
                "created_at": m.created_at.isoformat(),
            }
            for m in msgs
        ],
    }


class CustomerMessageBody(BaseModel):
    customer_id: str
    text: str
    timestamp: float
    signature: str


@router.post("/api/customer/reports/{report_id}/messages", status_code=201)
async def customer_send_message(
    report_id: str,
    body: CustomerMessageBody,
    session: Session = Depends(get_session),
):
    """Customer sends a message on their own report."""
    text = body.text.strip()[:_MAX_MSG_LEN]
    if not text:
        raise HTTPException(status_code=422, detail="Message text is required.")

    key_row = _verify_customer(
        report_id, body.customer_id, str(body.timestamp), body.signature, session
    )
    _assert_report_owner(report_id, body.customer_id, session)

    msg = BugReportMessage(
        report_id=report_id,
        sender="customer",
        author_name=key_row.customer_name,
        text=text,
        is_read_by_support=False,
        is_read_by_customer=True,
    )
    session.add(msg)
    session.commit()
    session.refresh(msg)

    return {
        "id": msg.id,
        "sender": msg.sender,
        "created_at": msg.created_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------

@router.get("/api/admin/reports/{report_id}/messages")
async def admin_get_messages(
    request: Request,
    report_id: str,
    authorization: Optional[str] = Header(default=None),
    session: Session = Depends(get_session),
):
    """Admin reads a message thread and marks customer messages as read."""
    _check_bearer(authorization)
    _check_ip(request)

    msgs = session.exec(
        select(BugReportMessage)
        .where(BugReportMessage.report_id == report_id)
        .order_by(col(BugReportMessage.created_at).asc())
    ).all()

    for m in msgs:
        if m.sender == "customer" and not m.is_read_by_support:
            m.is_read_by_support = True
            session.add(m)
    session.commit()

    return {
        "messages": [
            {
                "id": m.id,
                "sender": m.sender,
                "author_name": m.author_name,
                "text": m.text,
                "created_at": m.created_at.isoformat(),
                "is_read_by_customer": m.is_read_by_customer,
            }
            for m in msgs
        ]
    }


class AdminMessageBody(BaseModel):
    text: str
    author_name: str = "Support"


@router.post("/api/admin/reports/{report_id}/messages", status_code=201)
async def admin_send_message(
    request: Request,
    report_id: str,
    body: AdminMessageBody,
    authorization: Optional[str] = Header(default=None),
    session: Session = Depends(get_session),
):
    """Admin/support replies to a bug report."""
    _check_bearer(authorization)
    _check_ip(request)

    # Verify report exists
    report = session.exec(
        select(BugReport).where(BugReport.report_id == report_id)
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")

    text = body.text.strip()[:_MAX_MSG_LEN]
    if not text:
        raise HTTPException(status_code=422, detail="Message text is required.")

    msg = BugReportMessage(
        report_id=report_id,
        sender="support",
        author_name=body.author_name.strip()[:80] or "Support",
        text=text,
        is_read_by_support=True,
        is_read_by_customer=False,
    )
    session.add(msg)

    # Auto-set report to "open" when support first replies
    if report.status == "new":
        report.status = "open"
        session.add(report)

    session.commit()
    session.refresh(msg)

    return {
        "id": msg.id,
        "sender": msg.sender,
        "created_at": msg.created_at.isoformat(),
    }
