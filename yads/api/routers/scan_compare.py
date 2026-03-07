"""
Scan Comparison / Baseline Diff (#42)

Compare two ScanResult records for the same target+module and show
a structured diff of findings, summary values, and raw data.
"""
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select

from yads.api.templating import templates
from yads.auth.deps import get_current_user_html
from yads.database import get_session
from yads.models import ScanResult, Target, User

router = APIRouter(prefix="/scan-compare", tags=["analytics"])

from yads.core.module_registry import get_module_labels as _get_module_labels

MODULE_LABELS = {**_get_module_labels(), "cve_scanner": "CVE Scanner"}


def _flatten_value(val: Any, prefix: str = "") -> Dict[str, str]:
    """Flatten nested dict/list to dot-notation key=value pairs."""
    result = {}
    if isinstance(val, dict):
        for k, v in val.items():
            result.update(_flatten_value(v, f"{prefix}.{k}" if prefix else k))
    elif isinstance(val, list):
        for i, item in enumerate(val):
            if isinstance(item, (dict, list)):
                result.update(_flatten_value(item, f"{prefix}[{i}]"))
            else:
                result[f"{prefix}[{i}]"] = str(item)
    else:
        result[prefix] = str(val) if val is not None else ""
    return result


def _diff_summary(old: Dict, new: Dict) -> List[Dict]:
    """Diff summary/score fields — return list of changed key-value pairs."""
    changes = []
    all_keys = set(old.keys()) | set(new.keys())
    for k in sorted(all_keys):
        ov = old.get(k)
        nv = new.get(k)
        if ov == nv:
            continue
        changes.append({"key": k, "old": str(ov) if ov is not None else "—", "new": str(nv) if nv is not None else "—"})
    return changes


def _fingerprint_finding(f: Dict) -> str:
    """Canonical key for a finding to detect added/removed."""
    return (
        f.get("title") or f.get("issue") or f.get("id") or
        f.get("header") or f.get("check") or
        str(sorted(f.items()))
    )


def _diff_findings(old_findings: List[Dict], new_findings: List[Dict]) -> Dict:
    """Compare two finding lists: added, removed, kept."""
    old_map = {_fingerprint_finding(f): f for f in old_findings}
    new_map = {_fingerprint_finding(f): f for f in new_findings}

    added = [new_map[k] for k in new_map if k not in old_map]
    removed = [old_map[k] for k in old_map if k not in new_map]
    kept = [new_map[k] for k in new_map if k in old_map]
    return {"added": added, "removed": removed, "kept": kept}


def _can_view_target(user: User, target: Target) -> bool:
    if user.role == "admin" and user.tenant_id is None:
        return True
    return target.tenant_id == user.tenant_id


@router.get("/", response_class=HTMLResponse)
async def view_compare(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    target_id: Optional[int] = None,
    module: Optional[str] = None,
    a: Optional[int] = None,  # older result id
    b: Optional[int] = None,  # newer result id
):
    # --- Tenant-scoped targets for selector ---
    if user.role == "admin" and user.tenant_id is None:
        targets = session.exec(select(Target).where(Target.is_archived == False).order_by(Target.domain)).all()
    else:
        targets = session.exec(
            select(Target).where(Target.tenant_id == user.tenant_id, Target.is_archived == False).order_by(Target.domain)
        ).all()

    target_map = {t.id: t for t in targets}
    selected_target = target_map.get(target_id) if target_id else None

    # --- Module list for selected target ---
    available_modules: List[str] = []
    if selected_target:
        mods = session.exec(
            select(ScanResult.module_name)
            .where(ScanResult.target_id == selected_target.id)
            .distinct()
        ).all()
        available_modules = sorted(mods)

    # --- History list for target+module ---
    history: List[ScanResult] = []
    if selected_target and module:
        history = session.exec(
            select(ScanResult)
            .where(ScanResult.target_id == selected_target.id, ScanResult.module_name == module)
            .order_by(ScanResult.scanned_at.desc())
            .limit(50)
        ).all()

    # --- Diff computation ---
    diff = None
    result_a: Optional[ScanResult] = None
    result_b: Optional[ScanResult] = None
    error_msg = None

    if a and b:
        result_a = session.get(ScanResult, a)
        result_b = session.get(ScanResult, b)

        if not result_a or not result_b:
            error_msg = "One or both scan results not found."
        elif result_a.target_id != result_b.target_id:
            error_msg = "Cannot compare results from different targets."
        elif result_a.module_name != result_b.module_name:
            error_msg = "Cannot compare results from different modules."
        else:
            target = target_map.get(result_a.target_id)
            if not target or not _can_view_target(user, target):
                raise HTTPException(status_code=403, detail="Access denied")
            # Ensure older is A, newer is B
            if result_a.scanned_at > result_b.scanned_at:
                result_a, result_b = result_b, result_a

            data_a = result_a.data or {}
            data_b = result_b.data or {}

            findings_a = data_a.get("findings", [])
            findings_b = data_b.get("findings", [])
            summary_a = data_a.get("summary", {}) or {}
            summary_b = data_b.get("summary", {}) or {}

            # Score shortcut: many modules store score at top level
            if "score" in data_a and "summary" not in data_a:
                summary_a = {"score": data_a.get("score")}
            if "score" in data_b and "summary" not in data_b:
                summary_b = {"score": data_b.get("score")}

            diff = {
                "findings": _diff_findings(findings_a, findings_b),
                "summary": _diff_summary(summary_a, summary_b),
                "hash_changed": result_a.result_hash != result_b.result_hash,
                "findings_count_a": len(findings_a),
                "findings_count_b": len(findings_b),
                "delta": len(findings_b) - len(findings_a),
            }

            # Populate context for template
            if not selected_target and result_a:
                selected_target = target_map.get(result_a.target_id)
            if not module and result_a:
                module = result_a.module_name

    return templates.TemplateResponse("scan_compare.html", {
        "request": request,
        "user": user,
        "targets": targets,
        "target_id": target_id or (result_a.target_id if result_a else None),
        "selected_target": selected_target,
        "module": module,
        "available_modules": available_modules,
        "history": history,
        "module_labels": MODULE_LABELS,
        "result_a": result_a,
        "result_b": result_b,
        "diff": diff,
        "error_msg": error_msg,
    })
