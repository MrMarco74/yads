"""
Report category management: CRUD + assignment to BugReports.
All endpoints are admin-IP-gated via _check_ip.
"""
from fastapi import APIRouter, Depends, HTTPException, Form, Request
from fastapi.responses import RedirectResponse, JSONResponse
from sqlmodel import Session, select

from app.database import get_session
from app.models import ReportCategory, BugReport
from app.routers.admin_keys import _check_ip

router = APIRouter(prefix="/categories", tags=["categories"])

VALID_COLORS = {"blue", "green", "red", "yellow", "purple", "orange", "gray", "pink"}


@router.get("/", response_model=list[ReportCategory])
async def list_categories(
    session: Session = Depends(get_session),
    _: None = Depends(_check_ip),
):
    return session.exec(select(ReportCategory).order_by(ReportCategory.name)).all()


@router.post("/create", response_class=RedirectResponse)
async def create_category(
    request: Request,
    name: str = Form(...),
    color: str = Form("blue"),
    session: Session = Depends(get_session),
    _: None = Depends(_check_ip),
):
    name = name.strip()[:60]
    if not name:
        raise HTTPException(400, "Name darf nicht leer sein")
    color = color if color in VALID_COLORS else "blue"
    existing = session.exec(select(ReportCategory).where(ReportCategory.name == name)).first()
    if existing:
        raise HTTPException(409, f"Kategorie '{name}' existiert bereits")
    session.add(ReportCategory(name=name, color=color))
    session.commit()
    return RedirectResponse(url=str(request.headers.get("referer", "/reports")), status_code=303)


@router.post("/delete/{cat_id}", response_class=RedirectResponse)
async def delete_category(
    request: Request,
    cat_id: int,
    session: Session = Depends(get_session),
    _: None = Depends(_check_ip),
):
    cat = session.get(ReportCategory, cat_id)
    if not cat:
        raise HTTPException(404, "Kategorie nicht gefunden")
    # Clear references before deleting
    for report in session.exec(select(BugReport).where(BugReport.category_id == cat_id)).all():
        report.category_id = None
        session.add(report)
    session.delete(cat)
    session.commit()
    return RedirectResponse(url=str(request.headers.get("referer", "/reports")), status_code=303)


@router.post("/assign/{report_id}", response_class=JSONResponse)
async def assign_category(
    report_id: str,
    category_id: int | None = Form(default=None),
    session: Session = Depends(get_session),
    _: None = Depends(_check_ip),
):
    report = session.exec(select(BugReport).where(BugReport.report_id == report_id)).first()
    if not report:
        raise HTTPException(404, "Report nicht gefunden")
    if category_id is not None:
        cat = session.get(ReportCategory, category_id)
        if not cat:
            raise HTTPException(404, "Kategorie nicht gefunden")
    report.category_id = category_id
    session.add(report)
    session.commit()
    return {"ok": True, "category_id": category_id}
