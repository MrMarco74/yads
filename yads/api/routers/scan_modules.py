"""
Scan Module Management (#60)

Admin interface for:
  - Viewing all registered scanner modules
  - Enabling/disabling modules per tenant
  - Installing new modules via ZIP upload (platform admin only)
  - Removing custom-installed modules (platform admin only)
"""
import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlmodel import Session, select

from yads.api.templating import templates
from yads.auth.deps import PlatformAdminChecker, RoleChecker, get_current_user_html
from yads.core.module_registry import CATEGORIES, REGISTRY, ModuleDef, get_module_labels
from yads.database import get_session
from yads.models import InstalledModule, Tenant, TenantModuleConfig, User

router = APIRouter(prefix="/scan-modules", tags=["scan-modules"])

_CUSTOM_MODULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "modules", "custom"
)

CAT_LABELS = {c["id"]: c["label"] for c in CATEGORIES}
CAT_COLORS = {c["id"]: c["color"] for c in CATEGORIES}


def _get_enabled_map(session: Session, tenant_id: int) -> Dict[str, bool]:
    """Return {module_name: enabled} for a tenant. Missing rows = True (enabled)."""
    rows = session.exec(
        select(TenantModuleConfig).where(TenantModuleConfig.tenant_id == tenant_id)
    ).all()
    return {r.module_name: r.enabled for r in rows}


def _build_module_rows(session: Session, tenant_id: Optional[int]) -> List[Dict]:
    """Build display rows for all modules (registry + installed)."""
    enabled_map: Dict[str, bool] = {}
    if tenant_id:
        enabled_map = _get_enabled_map(session, tenant_id)

    rows = []
    for name, defn in REGISTRY.items():
        rows.append({
            "name": name,
            "label": defn.label,
            "label_de": defn.label_de,
            "category": defn.category,
            "cat_label": CAT_LABELS.get(defn.category, defn.category),
            "cat_color": CAT_COLORS.get(defn.category, "gray"),
            "finding_module": defn.finding_module,
            "custom": False,
            "enabled": enabled_map.get(name, True),
        })

    # Installed custom modules
    for im in session.exec(select(InstalledModule).where(InstalledModule.is_active == True)).all():
        if im.module_name not in REGISTRY:
            rows.append({
                "name": im.module_name,
                "label": im.label,
                "label_de": im.label_de,
                "category": im.category,
                "cat_label": CAT_LABELS.get(im.category, im.category),
                "cat_color": CAT_COLORS.get(im.category, "gray"),
                "finding_module": im.finding_module,
                "custom": True,
                "enabled": enabled_map.get(im.module_name, True),
                "version": im.version,
                "author": im.author,
                "description": im.description,
                "installed_at": im.installed_at,
            })

    return rows


# ---------------------------------------------------------------------------
# GET /scan-modules/
# ---------------------------------------------------------------------------
@router.get("/", response_class=HTMLResponse)
async def scan_modules_view(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin"])),
    tenant_id: Optional[int] = None,
    category: Optional[str] = None,
):
    is_platform_admin = user.role == "admin" and user.tenant_id is None

    # Tenant list (platform admin sees all; tenant_admin sees own)
    if is_platform_admin:
        tenants = session.exec(select(Tenant).order_by(Tenant.name)).all()
        active_tenant_id = tenant_id or (tenants[0].id if tenants else None)
    else:
        tenants = []
        active_tenant_id = user.tenant_id

    modules = _build_module_rows(session, active_tenant_id)
    if category:
        modules = [m for m in modules if m["category"] == category]

    return templates.TemplateResponse("scan_modules.html", {
        "request": request,
        "user": user,
        "modules": modules,
        "tenants": tenants,
        "active_tenant_id": active_tenant_id,
        "selected_category": category,
        "categories": CATEGORIES,
        "is_platform_admin": is_platform_admin,
    })


# ---------------------------------------------------------------------------
# POST /scan-modules/toggle — enable/disable a module for a tenant
# ---------------------------------------------------------------------------
@router.post("/toggle")
async def toggle_module(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin"])),
    tenant_id: int = Form(...),
    module_name: str = Form(...),
    enabled: bool = Form(...),
):
    is_platform_admin = user.role == "admin" and user.tenant_id is None
    # Tenant admin can only toggle their own tenant
    if not is_platform_admin and tenant_id != user.tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    existing = session.exec(
        select(TenantModuleConfig).where(
            TenantModuleConfig.tenant_id == tenant_id,
            TenantModuleConfig.module_name == module_name,
        )
    ).first()

    if existing:
        existing.enabled = enabled
        existing.updated_at = datetime.utcnow()
        existing.updated_by = user.id
        session.add(existing)
    else:
        session.add(TenantModuleConfig(
            tenant_id=tenant_id,
            module_name=module_name,
            enabled=enabled,
            updated_by=user.id,
        ))
    session.commit()

    redirect_url = f"/scan-modules/?tenant_id={tenant_id}"
    return RedirectResponse(redirect_url, status_code=303)


# ---------------------------------------------------------------------------
# POST /scan-modules/upload — install new module from ZIP (platform admin)
# ---------------------------------------------------------------------------
@router.post("/upload")
async def upload_module(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(PlatformAdminChecker()),
    module_zip: UploadFile = File(...),
):
    if not module_zip.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only ZIP files are accepted")

    tmpdir = tempfile.mkdtemp(prefix="yads_module_")
    try:
        zip_path = os.path.join(tmpdir, "upload.zip")
        content = await module_zip.read()
        with open(zip_path, "wb") as f:
            f.write(content)

        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(tmpdir)

        # Read manifest
        manifest_path = os.path.join(tmpdir, "module_manifest.json")
        if not os.path.exists(manifest_path):
            raise HTTPException(status_code=400, detail="module_manifest.json not found in ZIP")

        with open(manifest_path) as f:
            manifest = json.load(f)

        required_fields = ["module_name", "label", "module_file", "class_name"]
        for field in required_fields:
            if field not in manifest:
                raise HTTPException(status_code=400, detail=f"Missing field in manifest: {field}")

        module_name = manifest["module_name"]
        if module_name in REGISTRY:
            raise HTTPException(status_code=409, detail=f"Module '{module_name}' already exists in registry")

        existing_installed = session.exec(
            select(InstalledModule).where(InstalledModule.module_name == module_name)
        ).first()
        if existing_installed and existing_installed.is_active:
            raise HTTPException(status_code=409, detail=f"Module '{module_name}' is already installed")

        # Run setup script if present
        setup_log = ""
        for setup_file in ["setup.py", "setup.sh"]:
            setup_path = os.path.join(tmpdir, setup_file)
            if os.path.exists(setup_path):
                try:
                    if setup_file.endswith(".sh"):
                        cmd = ["bash", setup_path]
                    else:
                        cmd = ["python", setup_path]
                    result = subprocess.run(
                        cmd, cwd=tmpdir, capture_output=True, text=True, timeout=120
                    )
                    setup_log = result.stdout + result.stderr
                    if result.returncode != 0:
                        raise HTTPException(
                            status_code=500,
                            detail=f"Setup script failed (exit {result.returncode}): {setup_log[-500:]}"
                        )
                except subprocess.TimeoutExpired:
                    raise HTTPException(status_code=500, detail="Setup script timed out (120s)")
                break

        # Copy module file to custom modules dir
        module_file = manifest["module_file"]
        src = os.path.join(tmpdir, module_file)
        if not os.path.exists(src):
            raise HTTPException(status_code=400, detail=f"Module file '{module_file}' not found in ZIP")

        os.makedirs(_CUSTOM_MODULES_DIR, exist_ok=True)
        dest = os.path.join(_CUSTOM_MODULES_DIR, module_file)
        shutil.copy2(src, dest)

        module_path = f"yads.modules.custom.{module_file.replace('.py', '')}:{manifest['class_name']}"

        # Register in DB
        im = existing_installed or InstalledModule()
        im.module_name = module_name
        im.label = manifest.get("label", module_name)
        im.label_de = manifest.get("label_de", manifest.get("label", module_name))
        im.category = manifest.get("category", "active")
        im.version = manifest.get("version", "1.0.0")
        im.author = manifest.get("author", "")
        im.description = manifest.get("description", "")
        im.module_path = module_path
        im.requires_http = manifest.get("requires_http", False)
        im.requires_https = manifest.get("requires_https", False)
        im.default_on = manifest.get("default_on", False)
        im.finding_module = manifest.get("finding_module", True)
        im.extractor = manifest.get("extractor", "generic")
        im.installed_at = datetime.utcnow()
        im.installed_by = user.id
        im.is_active = True
        im.setup_log = setup_log or None

        session.add(im)
        session.commit()
        session.refresh(im)

        # Dynamically register in runtime registry
        _register_installed_module(im)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return RedirectResponse("/scan-modules/?installed=1", status_code=303)


# ---------------------------------------------------------------------------
# POST /scan-modules/{module_name}/delete — remove custom module (platform admin)
# ---------------------------------------------------------------------------
@router.post("/{module_name}/delete")
async def delete_module(
    module_name: str,
    session: Session = Depends(get_session),
    user: User = Depends(PlatformAdminChecker()),
):
    im = session.exec(
        select(InstalledModule).where(InstalledModule.module_name == module_name)
    ).first()
    if not im:
        raise HTTPException(status_code=404, detail="Module not found")
    if module_name in REGISTRY and not im:
        raise HTTPException(status_code=400, detail="Built-in modules cannot be deleted")

    im.is_active = False
    session.add(im)

    # Remove from runtime registry if present
    if module_name in REGISTRY:
        del REGISTRY[module_name]

    # Delete TenantModuleConfig rows
    configs = session.exec(
        select(TenantModuleConfig).where(TenantModuleConfig.module_name == module_name)
    ).all()
    for cfg in configs:
        session.delete(cfg)

    session.commit()
    return RedirectResponse("/scan-modules/", status_code=303)


# ---------------------------------------------------------------------------
# Helper: Register an InstalledModule in the runtime REGISTRY
# ---------------------------------------------------------------------------
def _register_installed_module(im: InstalledModule) -> None:
    """Add an installed module to the in-process REGISTRY dict."""
    defn = ModuleDef(
        name=im.module_name,
        label=im.label,
        label_de=im.label_de or im.label,
        category=im.category,
        module_path=im.module_path,
        worker_note=f"Running {im.label}...",
        requires_http=im.requires_http,
        requires_https=im.requires_https,
        default_on=im.default_on,
        finding_module=im.finding_module,
        extractor=im.extractor,
    )
    REGISTRY[im.module_name] = defn


def load_installed_modules_from_db(session: Session) -> None:
    """Called at startup to register custom modules into the runtime REGISTRY."""
    for im in session.exec(select(InstalledModule).where(InstalledModule.is_active == True)).all():
        if im.module_name not in REGISTRY:
            _register_installed_module(im)
