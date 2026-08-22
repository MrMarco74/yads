"""
DORA resilience-testing evidence export (#60, Art. 24-27).

DORA requires audit-ready evidence of resilience testing: test date, scope,
result, and remediation status. Rather than a new report type from scratch,
this assembles what already exists — ModuleState (test dates + scope) and
SecurityFinding (results + remediation status) — into one exportable,
audit-ready row-per-test-per-target document.
"""
from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from yads.database import get_session
from yads.auth.deps import get_current_active_user
from yads.models import Target, ModuleState, SecurityFinding, User
from yads.utils.export import generate_excel, generate_pdf

router = APIRouter(prefix="/dora-evidence", tags=["compliance"])


def _build_evidence_rows(session: Session, user: User) -> List[Dict[str, Any]]:
    target_query = select(Target)
    if user.tenant_id:
        target_query = target_query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        target_query = target_query.where(Target.tenant_id == None)  # noqa: E711
    targets = session.exec(target_query).all()
    target_map = {t.id: t.domain for t in targets}
    if not target_map:
        return []

    states = session.exec(select(ModuleState).where(ModuleState.target_id.in_(list(target_map.keys())))).all()

    findings = session.exec(select(SecurityFinding).where(SecurityFinding.target_id.in_(list(target_map.keys())))).all()
    findings_by_target: Dict[int, List[SecurityFinding]] = {}
    for f in findings:
        findings_by_target.setdefault(f.target_id, []).append(f)

    rows = []
    for s in states:
        domain = target_map.get(s.target_id, "?")
        tgt_findings = findings_by_target.get(s.target_id, [])
        module_findings = [f for f in tgt_findings if f.module == s.module_name]
        open_count = sum(1 for f in module_findings if f.status == "open")
        fixed_count = sum(1 for f in module_findings if f.status == "fixed")
        rows.append({
            "Target": domain,
            "Test (Module)": s.module_name,
            "Test Date": s.last_scanned_at.strftime("%Y-%m-%d %H:%M UTC") if s.last_scanned_at else "",
            "Findings Total": len(module_findings),
            "Findings Open": open_count,
            "Findings Fixed": fixed_count,
            "Result": "FAIL" if open_count else ("PASS (with history)" if module_findings else "PASS"),
        })

    rows.sort(key=lambda r: (r["Target"], r["Test (Module)"]))
    return rows


@router.get("/export/excel")
async def export_dora_evidence_excel(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
):
    rows = _build_evidence_rows(session, user)
    return generate_excel(rows, "dora_resilience_testing_evidence")


@router.get("/export/pdf")
async def export_dora_evidence_pdf(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
):
    rows = _build_evidence_rows(session, user)
    title = f"DORA Resilience Testing Evidence - generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
    return generate_pdf(rows, title, "dora_resilience_testing_evidence", orientation='L')
