"""
Third-Party Domains (backlog #21).

`yads/modules/external_resources_scanner.py` already collects, per target, every
external script/style/iframe origin a page loads plus a trust classification
(TRUSTED_ORIGINS / SUSPICIOUS_PATTERNS / mixed-content), but nothing aggregates
that across a tenant's whole target list. This is a tenant-wide, filterable view
of exactly that -- sortable/filterable by trust level, resource type, and how
many targets load from a given origin. Also useful for GDPR/DSGVO reporting:
which third parties does a tenant's estate actually load resources from.
"""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select

from yads.database import engine
from yads.models import Target, ScanResult, User
from yads.auth.deps import get_current_active_user
from yads.api.templating import templates

router = APIRouter(prefix="/api/third-party-domains", tags=["analytics"])
ui_router = APIRouter(prefix="/third-party-domains")


def get_session():
    with Session(engine) as session:
        yield session


def _get_third_party_domains_data(session: Session, user: User) -> Dict[str, Any]:
    """
    Aggregate `external_resources` scan results across every target in scope.
    Returns {"origins": [...], "scope_count": int}, one row per unique origin
    domain: trust level, resource types seen, and which targets load from it.
    """
    target_query = select(Target)
    if user.tenant_id:
        target_query = target_query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        target_query = target_query.where(Target.tenant_id == None)  # noqa: E711

    targets = session.exec(target_query).all()
    target_map = {t.id: t.domain for t in targets}
    if not targets:
        return {"origins": [], "scope_count": 0}

    results = session.exec(
        select(ScanResult.target_id, ScanResult.data).where(
            ScanResult.module_name == "external_resources",
            ScanResult.target_id.in_(list(target_map.keys())),
        )
    ).all()

    # Only the latest result per target matters — walk newest-first and skip repeats.
    seen_targets: set = set()
    origins: Dict[str, Dict[str, Any]] = {}

    for target_id, data in sorted(results, key=lambda r: r[0], reverse=True):
        if not data or target_id in seen_targets:
            continue
        seen_targets.add(target_id)
        t_domain = target_map.get(target_id, "?")

        for origin, info in (data.get("origins_summary") or {}).items():
            if origin not in origins:
                origins[origin] = {
                    "domain": origin,
                    "trusted": bool(info.get("trusted")),
                    "resource_types": set(),
                    "targets": set(),
                }
            origins[origin]["resource_types"].update(info.get("resource_types") or [])
            origins[origin]["targets"].add(t_domain)
            # An origin flagged untrusted anywhere in the estate stays untrusted.
            if not info.get("trusted"):
                origins[origin]["trusted"] = False

    final_list = []
    for origin, info in origins.items():
        final_list.append({
            "domain": origin,
            "trusted": info["trusted"],
            "resource_types": sorted(info["resource_types"]),
            "targets": sorted(info["targets"]),
            "target_count": len(info["targets"]),
        })
    final_list.sort(key=lambda x: x["target_count"], reverse=True)

    return {"origins": final_list, "scope_count": len(targets)}


@ui_router.get("/", response_class=HTMLResponse)
async def view_third_party_domains(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
):
    data = _get_third_party_domains_data(session, user)
    return templates.TemplateResponse("third_party_domains.html", {
        "request": request,
        "user": user,
        "origins": data["origins"],
        "scope_count": data["scope_count"],
    })


@router.get("/")
async def api_third_party_domains(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
):
    return _get_third_party_domains_data(session, user)


def _apex(domain: str) -> str:
    """Crude apex-domain extraction (last two labels) — used only to group
    third-party origins by likely-shared provider for concentration-risk
    flagging, not for anything security-sensitive."""
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _get_dora_register_data(session: Session, user: User) -> Dict[str, Any]:
    """
    DORA ICT third-party register (#59, Art. 28-30): feeds from #21's
    third-party-domains data + cloud_scanner's cloud asset findings into a
    single register, with a concentration-risk flag when one apex/provider
    accounts for an outsized share of all ICT third-party references.
    """
    tpd = _get_third_party_domains_data(session, user)

    target_query = select(Target)
    if user.tenant_id:
        target_query = target_query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        target_query = target_query.where(Target.tenant_id == None)  # noqa: E711
    targets = session.exec(target_query).all()
    target_map = {t.id: t.domain for t in targets}

    cloud_providers: Dict[str, set] = {}
    if target_map:
        results = session.exec(
            select(ScanResult.target_id, ScanResult.data).where(
                ScanResult.module_name == "cloud_scanner",
                ScanResult.target_id.in_(list(target_map.keys())),
            )
        ).all()
        seen_targets: set = set()
        for target_id, data in sorted(results, key=lambda r: r[0], reverse=True):
            if not data or target_id in seen_targets:
                continue
            seen_targets.add(target_id)
            for asset in data.get("assets") or []:
                provider = asset.get("provider") or "Unknown Cloud Provider"
                cloud_providers.setdefault(provider, set()).add(target_map.get(target_id, "?"))

    register = []
    for o in tpd["origins"]:
        register.append({
            "provider": o["domain"], "apex": _apex(o["domain"]),
            "category": "Third-party web resource", "trusted": o["trusted"],
            "affected_targets": o["targets"], "target_count": o["target_count"],
        })
    for provider, target_domains in cloud_providers.items():
        register.append({
            "provider": provider, "apex": provider,
            "category": "Cloud storage provider", "trusted": False,
            "affected_targets": sorted(target_domains), "target_count": len(target_domains),
        })

    # Concentration risk (#59): apex domains ranked by how many distinct
    # targets reference something under them — a real "80% of critical
    # vendors share one host" signal, not just a raw origin count.
    apex_target_union: Dict[str, set] = {}
    for row in register:
        apex_target_union.setdefault(row["apex"], set()).update(row["affected_targets"])
    total_targets_with_any = len(set().union(*apex_target_union.values())) if apex_target_union else 0

    concentration = []
    if total_targets_with_any:
        for apex, tgt_set in sorted(apex_target_union.items(), key=lambda kv: -len(kv[1])):
            pct = round(100 * len(tgt_set) / total_targets_with_any, 1)
            if pct >= 30:  # only flag apexes covering a meaningful share
                concentration.append({"apex": apex, "target_count": len(tgt_set), "pct": pct})

    register.sort(key=lambda r: r["target_count"], reverse=True)
    return {"register": register, "concentration": concentration, "scope_count": tpd["scope_count"]}


@ui_router.get("/dora-register", response_class=HTMLResponse)
async def view_dora_register(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
):
    data = _get_dora_register_data(session, user)
    return templates.TemplateResponse("dora_register.html", {
        "request": request, "user": user, **data,
    })


@router.get("/dora-register/export")
async def export_dora_register_csv(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
):
    import csv
    import io
    from fastapi.responses import StreamingResponse

    data = _get_dora_register_data(session, user)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Provider", "Category", "Affected Targets", "Target Count", "Trusted"])
    for row in data["register"]:
        writer.writerow([row["provider"], row["category"], "; ".join(row["affected_targets"]), row["target_count"], row["trusted"]])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=dora_ict_register.csv"},
    )
