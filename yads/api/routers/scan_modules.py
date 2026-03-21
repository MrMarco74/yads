"""
Scan Module Management (#60)

Admin interface for:
  - Viewing all registered scanner modules
  - Enabling/disabling modules per tenant
  - Installing new modules via ZIP upload (platform admin only)
  - Removing custom-installed modules (platform admin only)
"""
import base64
import hashlib
import json
import os
import re
import shutil
import tempfile
import zipfile
from datetime import datetime
from typing import Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
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


def _verify_module_signature(zip_bytes: bytes, signature_b64: Optional[str]) -> None:
    """
    Verify Ed25519 signature over SHA-256(zip_bytes).

    If MODULE_SIGNING_PUBLIC_KEY is configured, a valid signature is required.
    If it is not configured, the check is skipped (unsigned modules allowed).

    Raises HTTPException 400/403 on failure.
    """
    from yads.config import settings

    pubkey_b64 = settings.MODULE_SIGNING_PUBLIC_KEY
    if not pubkey_b64:
        if settings.MODULE_SIGNING_DISABLED:
            return  # Signing explicitly disabled by operator
        raise HTTPException(
            status_code=403,
            detail=(
                "Module signing is enforced by default. "
                "Configure MODULE_SIGNING_PUBLIC_KEY or set MODULE_SIGNING_DISABLED=true "
                "to explicitly allow unsigned uploads."
            )
        )

    if not signature_b64:
        raise HTTPException(
            status_code=403,
            detail="Module signing is enforced. Upload must include an Ed25519 signature."
        )

    try:
        raw_key = base64.b64decode(pubkey_b64)
        try:
            pub: Ed25519PublicKey = serialization.load_pem_public_key(raw_key)  # type: ignore[assignment]
        except ValueError:
            pub: Ed25519PublicKey = serialization.load_der_public_key(raw_key)  # type: ignore[assignment]

        # Normalise base64 padding
        sig_padded = signature_b64 + "=" * (-len(signature_b64) % 4)
        sig = base64.urlsafe_b64decode(sig_padded)

        digest = hashlib.sha256(zip_bytes).digest()
        pub.verify(sig, digest)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid module signature.")


def _get_enabled_map(session: Session, tenant_id: int) -> Dict[str, bool]:
    """Return {module_name: enabled} for a tenant. Missing rows = True (enabled)."""
    rows = session.exec(
        select(TenantModuleConfig).where(TenantModuleConfig.tenant_id == tenant_id)
    ).all()
    return {r.module_name: r.enabled for r in rows}


def _get_custom_module_filepath(im: InstalledModule) -> Optional[str]:
    """Derive the physical file path from an InstalledModule's module_path.

    module_path format: "yads.modules.custom.<stem>:<ClassName>"
    Returns the expected file path, or None if the format is unexpected.
    """
    try:
        pkg_part = im.module_path.split(":")[0]  # "yads.modules.custom.my_scanner"
        parts = pkg_part.split(".")
        # Reconstruct relative to _CUSTOM_MODULES_DIR
        if len(parts) >= 4 and parts[0] == "yads" and parts[1] == "modules" and parts[2] == "custom":
            filename = parts[3] + ".py"
            return os.path.join(_CUSTOM_MODULES_DIR, filename)
    except Exception:
        pass
    return None


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
            "file_missing": False,
        })

    # Installed custom modules (active + auto-deactivated with missing files)
    all_installed = session.exec(select(InstalledModule)).all()
    for im in all_installed:
        if im.module_name in REGISTRY:
            continue  # Built-in module, already listed above

        # Check if physical file exists on disk
        filepath = _get_custom_module_filepath(im)
        file_missing = filepath is not None and not os.path.exists(filepath)

        # Skip intentionally deleted modules (inactive AND file not missing).
        # Only show inactive modules when the file is missing (auto-deactivated
        # by the startup health check), so the admin can re-upload.
        if not im.is_active and not file_missing:
            continue

        rows.append({
            "name": im.module_name,
            "label": im.label,
            "label_de": im.label_de,
            "category": im.category,
            "cat_label": CAT_LABELS.get(im.category, im.category),
            "cat_color": CAT_COLORS.get(im.category, "gray"),
            "finding_module": im.finding_module,
            "custom": True,
            "enabled": enabled_map.get(im.module_name, True) if im.is_active else False,
            "version": im.version,
            "author": im.author,
            "description": im.description,
            "installed_at": im.installed_at,
            "file_missing": file_missing,
            "is_active": im.is_active,
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

    # Group by category in defined order
    cat_order = [c["id"] for c in CATEGORIES]
    grouped: list = []
    for cat in CATEGORIES:
        cat_modules = [m for m in modules if m["category"] == cat["id"]]
        if cat_modules:
            grouped.append({"cat": cat, "modules": cat_modules})
    other = [m for m in modules if m["category"] not in set(cat_order)]
    if other:
        grouped.append({"cat": {"id": "other", "label": "Other", "color": "gray"}, "modules": other})

    return templates.TemplateResponse("scan_modules.html", {
        "request": request,
        "user": user,
        "modules": modules,
        "grouped_modules": grouped,
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
    signature: Optional[str] = Form(None),
):
    if not module_zip.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only ZIP files are accepted")

    tmpdir = tempfile.mkdtemp(prefix="yads_module_")
    try:
        zip_path = os.path.join(tmpdir, "upload.zip")
        content = await module_zip.read()

        _verify_module_signature(content, signature)

        with open(zip_path, "wb") as f:
            f.write(content)

        with zipfile.ZipFile(zip_path, "r") as zf:
            # Zip slip protection: reject members that escape tmpdir
            resolved_tmp = os.path.realpath(tmpdir)
            for member in zf.namelist():
                member_path = os.path.realpath(os.path.join(tmpdir, member))
                if not member_path.startswith(resolved_tmp + os.sep):
                    raise HTTPException(
                        status_code=400,
                        detail=f"Malicious ZIP: path traversal in member '{member}'"
                    )
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

        # Validate module_name and class_name are safe Python identifiers
        _IDENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,63}$')
        if not _IDENT_RE.match(module_name):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid module_name '{module_name}': must be a valid Python identifier (a-z, 0-9, _)."
            )
        class_name = manifest["class_name"]
        if not _IDENT_RE.match(class_name):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid class_name '{class_name}': must be a valid Python identifier."
            )

        if module_name in REGISTRY:
            raise HTTPException(status_code=409, detail=f"Module '{module_name}' already exists in registry")

        existing_installed = session.exec(
            select(InstalledModule).where(InstalledModule.module_name == module_name)
        ).first()
        if existing_installed and existing_installed.is_active:
            raise HTTPException(status_code=409, detail=f"Module '{module_name}' is already installed")

        # Reject ZIPs that contain executable setup scripts (RCE prevention)
        for setup_file in ["setup.py", "setup.sh"]:
            if os.path.exists(os.path.join(tmpdir, setup_file)):
                raise HTTPException(
                    status_code=400,
                    detail=f"Module ZIP must not contain '{setup_file}'. "
                           "Setup scripts are not executed for security reasons."
                )

        # Copy module file to custom modules dir
        module_file = manifest["module_file"]

        # Prevent path traversal: module_file must be a plain filename ending in .py
        if (os.sep in module_file or "/" in module_file or "\\" in module_file
                or not module_file.endswith(".py") or module_file.startswith(".")):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid module_file '{module_file}': must be a plain .py filename with no path separators."
            )

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
        im.setup_log = None

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
    """Called at startup to register custom modules into the runtime REGISTRY.

    Performs a filesystem health check for each active InstalledModule:
      - If the physical .py file exists: register normally.
      - If the file is missing (e.g. Docker image wiped without volume):
        deactivate the DB record and log a warning instead of crashing on import.
    """
    import logging
    logger = logging.getLogger("yads.scan_modules")

    for im in session.exec(select(InstalledModule).where(InstalledModule.is_active == True)).all():
        if im.module_name in REGISTRY:
            continue

        # Verify the physical module file still exists on disk
        filepath = _get_custom_module_filepath(im)
        if filepath and not os.path.exists(filepath):
            logger.warning(
                "Custom module '%s' is registered in DB but physical file is missing (%s). "
                "Deactivating to prevent import crash. Re-upload via Plugin Manager to restore.",
                im.module_name, filepath,
            )
            im.is_active = False
            session.add(im)
            session.commit()
            continue

        _register_installed_module(im)
