"""
NIS2 Article 21 minimum-measures mapping (#61).

Maps YADS's actual scan coverage against the 10 minimum security measures
NIS2 Article 21 requires. Each row's status is computed from real scan data
(module presence + findings for this tenant), not a static checklist —
"covered" means YADS actually has recent evidence for that measure, not
just that a corresponding module theoretically exists.
"""
from datetime import datetime, timedelta
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select

from yads.database import get_session
from yads.auth.deps import get_current_user_html
from yads.models import Target, ScanResult, User
from yads.api.templating import templates

router = APIRouter(prefix="/nis2-measures", tags=["compliance"])

# (measure_number, title, description, evidence_modules)
_MEASURES = [
    (1, "Risikoanalyse & Sicherheitskonzepte", "Regelmäßige Bewertung der Angriffsfläche und Schwachstellen.", ["nuclei_scanner", "web_analyzer"]),
    (2, "Incident Handling", "Erkennung und Reaktion auf Sicherheitsvorfälle.", ["security_alert"]),  # webhook event_type, checked separately
    (3, "Business Continuity / Backup", "Notfallwiederherstellung, Backup-Strategie.", []),  # infra-level, not scan-derivable
    (4, "Supply-Chain-Sicherheit", "Absicherung von Drittanbietern/Abhängigkeiten.", ["dependency_confusion"]),
    (5, "Schwachstellen-Management", "Systematisches Erkennen und Beheben von Schwachstellen (inkl. Offenlegung).", ["nuclei_scanner", "banner_grabber"]),
    (6, "Wirksamkeitsbewertung der Maßnahmen", "Messung, ob getroffene Maßnahmen tatsächlich wirken.", ["waf_detector"]),
    (7, "Basis-Cyberhygiene & Schulung", "Grundlegende Sicherheitspraktiken, Versions-/Patch-Hygiene.", ["banner_grabber", "wayback_scanner"]),
    (8, "Kryptographie & Verschlüsselung", "TLS-Konfiguration, Zertifikatsmanagement, PQC-Readiness.", ["ssl_scanner", "tls_deep_scanner"]),
    (9, "Zugriffskontrolle & Asset-Management", "Zugriffsschutz, Exponierte Admin-Oberflächen.", ["login_scanner", "waf_detector"]),
    (10, "MFA & sichere Kommunikation", "Multi-Faktor-Authentifizierung auf Login-Oberflächen.", ["login_scanner"]),
]


@router.get("/", response_class=HTMLResponse)
async def view_nis2_measures(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    target_query = select(Target)
    if user.tenant_id:
        target_query = target_query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        target_query = target_query.where(Target.tenant_id == None)  # noqa: E711
    target_ids = [t.id for t in session.exec(target_query).all()]

    recent_cutoff = datetime.utcnow() - timedelta(days=90)
    modules_with_recent_data: set = set()
    if target_ids:
        rows = session.exec(
            select(ScanResult.module_name).where(
                ScanResult.target_id.in_(target_ids),
                ScanResult.scanned_at >= recent_cutoff,
            ).distinct()
        ).all()
        modules_with_recent_data = set(rows)

    measures: List[Dict[str, Any]] = []
    for num, title, desc, evidence_modules in _MEASURES:
        if not evidence_modules:
            status = "not_tracked"
        else:
            covered = [m for m in evidence_modules if m in modules_with_recent_data]
            if len(covered) == len(evidence_modules):
                status = "covered"
            elif covered:
                status = "partial"
            else:
                status = "gap"
        measures.append({
            "number": num, "title": title, "description": desc,
            "evidence_modules": evidence_modules, "status": status,
        })

    covered_count = sum(1 for m in measures if m["status"] == "covered")

    return templates.TemplateResponse("nis2_measures.html", {
        "request": request, "user": user,
        "measures": measures, "covered_count": covered_count, "total_count": len(measures),
    })
