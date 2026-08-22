"""
Metadata-Leak Aggregation (backlog #71).

`yads/modules/metadata_scanner.py` extracts document metadata (author names,
internal file paths, software versions) per target and stores individual
findings/OSINTIntelligence rows, but nothing aggregates it across a tenant's
whole target list. The real signal is recurrence: the same internal username
or internal file-system path showing up in documents from *multiple* targets
is a much stronger indicator of a genuine identity/infrastructure leak than
any single document taken alone.
"""
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select

from yads.database import engine
from yads.models import Target, ScanResult, User
from yads.auth.deps import get_current_active_user
from yads.api.templating import templates

router = APIRouter(prefix="/api/metadata-leaks", tags=["analytics"])
ui_router = APIRouter(prefix="/metadata-leaks")


def get_session():
    with Session(engine) as session:
        yield session


def _get_metadata_leaks_data(session: Session, user: User) -> Dict[str, Any]:
    target_query = select(Target)
    if user.tenant_id:
        target_query = target_query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        target_query = target_query.where(Target.tenant_id == None)  # noqa: E711

    targets = session.exec(target_query).all()
    target_map = {t.id: t.domain for t in targets}
    if not targets:
        return {"authors": [], "software": [], "internal_paths": [], "scope_count": 0}

    results = session.exec(
        select(ScanResult.target_id, ScanResult.data).where(
            ScanResult.module_name == "metadata_scanner",
            ScanResult.target_id.in_(list(target_map.keys())),
        )
    ).all()

    seen_targets: set = set()
    authors: Dict[str, set] = {}
    software: Dict[str, set] = {}
    paths: Dict[str, set] = {}

    for target_id, data in sorted(results, key=lambda r: r[0], reverse=True):
        if not data or target_id in seen_targets:
            continue
        seen_targets.add(target_id)
        t_domain = target_map.get(target_id, "?")

        for item in data.get("metadata_items") or []:
            name = item.get("author") or item.get("last_modified_by")
            if name:
                authors.setdefault(name, set()).add(t_domain)
            for sw_field in ("creator", "producer"):
                sw = item.get(sw_field)
                if sw:
                    software.setdefault(sw, set()).add(t_domain)
            for path in item.get("internal_paths") or []:
                paths.setdefault(path, set()).add(t_domain)

    def _to_list(d: Dict[str, set]) -> List[Dict[str, Any]]:
        rows = [{"value": k, "targets": sorted(v), "target_count": len(v)} for k, v in d.items()]
        rows.sort(key=lambda r: r["target_count"], reverse=True)
        return rows

    return {
        "authors": _to_list(authors),
        "software": _to_list(software),
        "internal_paths": _to_list(paths),
        "scope_count": len(targets),
    }


@ui_router.get("/", response_class=HTMLResponse)
async def view_metadata_leaks(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
):
    data = _get_metadata_leaks_data(session, user)
    return templates.TemplateResponse("metadata_leaks.html", {
        "request": request,
        "user": user,
        **data,
    })


@router.get("/")
async def api_metadata_leaks(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
):
    return _get_metadata_leaks_data(session, user)
