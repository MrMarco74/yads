"""
Extension Hub (#60 — successor to scan_modules / Plugin Manager)

Admin interface for:
  - Viewing all registered scanner modules
  - Enabling/disabling modules per tenant
  - Installing new add-ons via individual ZIP or bundle ZIP upload (platform admin only)
  - Removing custom-installed add-ons (platform admin only)
  - Browsing the add-on store catalog (online + air-gap/embedded fallback)
  - Checking for updates against the catalog
"""
import json
import os
import re
import shutil
import tempfile
import zipfile
from datetime import datetime
from typing import Dict, List, Optional

import httpx
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlmodel import Session, select

from yads.api.templating import templates
from yads.core.module_signing import compute_file_hash, recheck_file_integrity, sign_zip, verify_module_signature
from yads.auth.deps import PlatformAdminChecker, RoleChecker, get_current_user_html
from yads.core.module_registry import CATEGORIES, REGISTRY, ModuleDef, get_module_labels
from yads.database import get_session
from yads.models import InstalledModule, SystemConfig, Tenant, TenantModuleConfig, User

router = APIRouter(prefix="/addons", tags=["addons"])

from yads.core.custom_modules_loader import (
    load_installed_modules_from_db,
    _register_installed_module,
    _get_custom_module_filepath,
    _CUSTOM_MODULES_DIR
)

CAT_LABELS = {c["id"]: c["label"] for c in CATEGORIES}
CAT_COLORS = {c["id"]: c["color"] for c in CATEGORIES}

# ---------------------------------------------------------------------------
# Hardcoded fallback catalog (shown when online fetch and cached catalog both fail)
# ---------------------------------------------------------------------------
_FALLBACK_CATALOG = [
    {
        "module_name": "cookie_consent_audit",
        "label": "Cookie Consent Audit",
        "label_de": "Cookie-Einwilligung Audit",
        "description": "Detects pre-consent tracking, dark patterns, and GDPR consent violations using dynamic browser analysis.",
        "category": "compliance",
        "version": "1.0.0",
        "author": "YADS Security",
        "tags": ["GDPR", "Compliance", "Cookies"],
        "download_url": "https://yads-security.com/files/modules/cookie_consent_audit.zip",
    },
    {
        "module_name": "data_residency_check",
        "label": "Data Residency Check",
        "label_de": "Datenspeicherort-Prüfung",
        "description": "Identifies third-party data flows that cross jurisdictional boundaries, mapping CDN and analytics endpoints to their geographic locations.",
        "category": "compliance",
        "version": "1.0.0",
        "author": "YADS Security",
        "tags": ["GDPR", "Data Residency", "Privacy"],
        "download_url": "https://yads-security.com/files/modules/data_residency_check.zip",
    },
    {
        "module_name": "kubernetes_exposure",
        "label": "Kubernetes Exposure Scanner",
        "label_de": "Kubernetes Exposition-Scanner",
        "description": "Scans for exposed Kubernetes API servers, dashboards, and management interfaces accessible from the public internet.",
        "category": "exposure",
        "version": "1.0.0",
        "author": "YADS Security",
        "tags": ["Kubernetes", "Container", "Cloud"],
        "download_url": "https://yads-security.com/files/modules/kubernetes_exposure.zip",
    },
    {
        "module_name": "third_party_risk",
        "label": "Third-Party Risk Monitor",
        "label_de": "Drittanbieter-Risiko-Monitor",
        "description": "Evaluates the security posture of third-party scripts and services loaded by target web applications.",
        "category": "threat",
        "version": "1.0.0",
        "author": "YADS Security",
        "tags": ["Supply Chain", "Third Party", "Risk"],
        "download_url": "https://yads-security.com/files/modules/third_party_risk.zip",
    },
    {
        "module_name": "mobile_app_monitor",
        "label": "Mobile App Monitor",
        "label_de": "Mobile-App-Monitor",
        "description": "Discovers associated mobile applications (iOS/Android), checks app store metadata and detects leaked API endpoints in app bundles.",
        "category": "recon",
        "version": "1.0.0",
        "author": "YADS Security",
        "tags": ["Mobile", "iOS", "Android", "OSINT"],
        "download_url": "https://yads-security.com/files/modules/mobile_app_monitor.zip",
    },
]

_CATALOG_ONLINE_URL = "https://yads-security.com/files/modules/catalog.json"
_CATALOG_DB_KEY = "addon_store_catalog"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _get_enabled_map(session: Session, tenant_id: int) -> Dict[str, bool]:
    """Return {module_name: enabled} for a tenant. Missing rows = True (enabled)."""
    rows = session.exec(
        select(TenantModuleConfig).where(TenantModuleConfig.tenant_id == tenant_id)
    ).all()
    return {r.module_name: r.enabled for r in rows}


def _build_module_rows(session: Session, tenant_id: Optional[int]) -> List[Dict]:
    from datetime import timedelta
    _new_threshold = datetime.utcnow() - timedelta(days=7)
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
            "passive": defn.passive,
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
            "passive": getattr(im, "passive", True),
            "custom": True,
            "enabled": enabled_map.get(im.module_name, True) if im.is_active else False,
            "version": im.version,
            "author": im.author,
            "description": im.description,
            "installed_at": im.installed_at,
            "file_missing": file_missing,
            "is_active": im.is_active,
            "signature": im.signature,
            "file_hash": im.file_hash,
            "is_new": im.installed_at is not None and im.installed_at > _new_threshold,
        })

    return rows


def _fetch_catalog(session: Session) -> List[Dict]:
    """Return catalog: try online → DB cache → hardcoded fallback."""
    # 1. Try online
    try:
        resp = httpx.get(_CATALOG_ONLINE_URL, timeout=5.0, follow_redirects=True)
        if resp.status_code == 200:
            data = resp.json()
            addons = data.get("addons", data) if isinstance(data, dict) else data
            if isinstance(addons, list) and addons:
                # Persist to DB so future page loads use the latest version
                try:
                    cached = session.get(SystemConfig, _CATALOG_DB_KEY)
                    if cached:
                        cached.value = json.dumps(addons)
                    else:
                        session.add(SystemConfig(key=_CATALOG_DB_KEY, value=json.dumps(addons)))
                    session.commit()
                except Exception:
                    pass
                return addons
    except Exception:
        pass

    # 2. Try DB cache (from last bundle upload)
    cached = session.get(SystemConfig, _CATALOG_DB_KEY)
    if cached and cached.value:
        try:
            data = json.loads(cached.value)
            addons = data.get("addons", data) if isinstance(data, dict) else data
            if isinstance(addons, list) and addons:
                return addons
        except Exception:
            pass

    # 3. Hardcoded fallback
    return _FALLBACK_CATALOG


def _install_single_zip(
    content: bytes,
    signature: Optional[str],
    user: User,
    session: Session,
    tmpdir: str,
) -> Dict:
    """
    Install a single module ZIP. Returns a dict with install result info.
    Raises HTTPException on validation errors.
    """
    if not signature:
        signature = sign_zip(content)
    verify_module_signature(content, signature)

    zip_path = os.path.join(tmpdir, "upload.zip")
    with open(zip_path, "wb") as f:
        f.write(content)

    with zipfile.ZipFile(zip_path, "r") as zf:
        resolved_tmp = os.path.realpath(tmpdir)
        for member in zf.namelist():
            member_path = os.path.realpath(os.path.join(tmpdir, member))
            if not member_path.startswith(resolved_tmp + os.sep):
                raise HTTPException(
                    status_code=400,
                    detail=f"Malicious ZIP: path traversal in member '{member}'"
                )
        zf.extractall(tmpdir)

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
    _IDENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,63}$')
    if not _IDENT_RE.match(module_name):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid module_name '{module_name}': must be a valid Python identifier."
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
    is_update = existing_installed and existing_installed.is_active

    # Reject ZIPs that contain executable setup scripts (RCE prevention)
    for setup_file in ["setup.py", "setup.sh"]:
        if os.path.exists(os.path.join(tmpdir, setup_file)):
            raise HTTPException(
                status_code=400,
                detail=f"Module ZIP must not contain '{setup_file}'. "
                       "Setup scripts are not executed for security reasons."
            )

    module_file = manifest["module_file"]
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
    im.passive = manifest.get("passive", True)
    im.installed_at = datetime.utcnow()
    im.installed_by = user.id
    im.is_active = True
    im.setup_log = None
    im.signature = signature
    im.file_hash = compute_file_hash(dest)

    session.add(im)
    session.commit()
    session.refresh(im)

    # Disable for all existing tenants by default
    tenants_all = session.exec(select(Tenant)).all()
    for _t in tenants_all:
        _existing_cfg = session.exec(
            select(TenantModuleConfig).where(
                TenantModuleConfig.tenant_id == _t.id,
                TenantModuleConfig.module_name == module_name,
            )
        ).first()
        if not _existing_cfg:
            session.add(TenantModuleConfig(tenant_id=_t.id, module_name=module_name, enabled=False))
    session.commit()

    _register_installed_module(im)

    return {
        "module_name": module_name,
        "label": im.label,
        "version": im.version,
        "updated": is_update,
    }


# ---------------------------------------------------------------------------
# GET /addons/ — main page
# ---------------------------------------------------------------------------
@router.get("/", response_class=HTMLResponse)
async def addons_view(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(PlatformAdminChecker()),
):
    modules = _build_module_rows(session, tenant_id=None)

    # Catalog for store section
    catalog = _fetch_catalog(session)

    # Build update map: catalog_version by module_name
    catalog_version_map = {a["module_name"]: a.get("version", "0.0.0") for a in catalog}

    # Annotate installed custom modules with update_available
    installed_custom = [m for m in modules if m.get("custom")]
    for m in installed_custom:
        cat_ver = catalog_version_map.get(m["name"])
        if cat_ver and m.get("version") and _version_gt(cat_ver, m["version"]):
            m["update_available"] = True
            m["catalog_version"] = cat_ver
        else:
            m["update_available"] = False

    # Group by category
    cat_order = [c["id"] for c in CATEGORIES]
    grouped: list = []
    for cat in CATEGORIES:
        cat_modules = [m for m in modules if m["category"] == cat["id"]]
        if cat_modules:
            grouped.append({"cat": cat, "modules": cat_modules})
    other = [m for m in modules if m["category"] not in set(cat_order)]
    if other:
        grouped.append({"cat": {"id": "other", "label": "Other", "color": "gray"}, "modules": other})

    from yads.config import settings as _s
    from yads.core.module_signing import YADS_OFFICIAL_PUBLIC_KEY
    if _s.MODULE_SIGNING_DISABLED:
        _key_source = "disabled"
    elif _s.MODULE_SIGNING_PUBLIC_KEY:
        _key_source = "operator"
    elif YADS_OFFICIAL_PUBLIC_KEY:
        _key_source = "official"
    else:
        _key_source = "none"

    signing_status = {
        "disabled": _s.MODULE_SIGNING_DISABLED,
        "auto_sign": bool(_s.MODULE_SIGNING_PRIVATE_KEY_PATH),
        "key_source": _key_source,
        "key_path_name": os.path.basename(_s.MODULE_SIGNING_PRIVATE_KEY_PATH) if _s.MODULE_SIGNING_PRIVATE_KEY_PATH else None,
    }

    return templates.TemplateResponse("addons.html", {
        "request": request,
        "user": user,
        "modules": modules,
        "grouped_modules": grouped,
        "categories": CATEGORIES,
        "is_platform_admin": True,
        "signing_status": signing_status,
        "catalog": catalog,
        "signing_info": signing_status,
    })


# ---------------------------------------------------------------------------
# POST /addons/toggle — enable/disable a module for a tenant
# ---------------------------------------------------------------------------
@router.post("/toggle")
async def toggle_module(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(PlatformAdminChecker()),
    tenant_id: int = Form(...),
    module_name: str = Form(...),
    enabled: bool = Form(...),
):
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

    redirect_url = f"/addons/?tenant_id={tenant_id}"
    return RedirectResponse(redirect_url, status_code=303)


# ---------------------------------------------------------------------------
# POST /addons/preview — parse manifest from ZIP, no install (platform admin)
# ---------------------------------------------------------------------------
@router.post("/preview")
async def preview_module(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(PlatformAdminChecker()),
    module_zip: UploadFile = File(...),
):
    if not module_zip.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only ZIP files are accepted")

    content = await module_zip.read()
    if len(content) > 50 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="ZIP file too large (max 50 MB)")

    tmpdir = tempfile.mkdtemp(prefix="yads_preview_")
    try:
        zip_path = os.path.join(tmpdir, "upload.zip")
        with open(zip_path, "wb") as f:
            f.write(content)

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                names = zf.namelist()

                # --- Bundle detection ---
                if "bundle_manifest.json" in names:
                    with zf.open("bundle_manifest.json") as bm:
                        bundle_manifest = json.load(bm)
                    modules_list = bundle_manifest.get("modules", [])
                    return JSONResponse({
                        "is_bundle": True,
                        "bundle_version": bundle_manifest.get("bundle_version", "1.0.0"),
                        "yads_min_version": bundle_manifest.get("yads_min_version", ""),
                        "modules": modules_list,
                        "files_in_zip": names,
                        "warnings": [],
                    })

                # --- Single module ---
                if "module_manifest.json" not in names:
                    raise HTTPException(status_code=400, detail="module_manifest.json not found in ZIP (and no bundle_manifest.json either)")
                with zf.open("module_manifest.json") as mf:
                    manifest = json.load(mf)
        except zipfile.BadZipFile:
            raise HTTPException(status_code=400, detail="Invalid ZIP file")

        required_fields = ["module_name", "label", "module_file", "class_name"]
        for field in required_fields:
            if field not in manifest:
                raise HTTPException(status_code=400, detail=f"Missing required field in manifest: '{field}'")

        module_name = manifest["module_name"]
        _IDENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,63}$')
        if not _IDENT_RE.match(module_name):
            raise HTTPException(status_code=400, detail=f"Invalid module_name '{module_name}'")

        already_installed = module_name in REGISTRY
        existing_db = session.exec(
            select(InstalledModule).where(InstalledModule.module_name == module_name, InstalledModule.is_active == True)
        ).first()

        warnings = []
        if already_installed and not existing_db:
            warnings.append("A built-in module with this name already exists — installation will be blocked.")
        if existing_db:
            warnings.append(f"Module '{module_name}' is already installed (v{existing_db.version}). Re-uploading will replace it.")

        return JSONResponse({
            "is_bundle": False,
            "module_name": module_name,
            "label": manifest.get("label", module_name),
            "label_de": manifest.get("label_de", ""),
            "version": manifest.get("version", "—"),
            "author": manifest.get("author", "—"),
            "description": manifest.get("description", ""),
            "category": manifest.get("category", "active"),
            "passive": manifest.get("passive", True),
            "module_file": manifest.get("module_file", ""),
            "class_name": manifest.get("class_name", ""),
            "requires_http": manifest.get("requires_http", False),
            "requires_https": manifest.get("requires_https", False),
            "default_on": manifest.get("default_on", False),
            "finding_module": manifest.get("finding_module", True),
            "files_in_zip": names,
            "warnings": warnings,
        })
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Shared install helper — used by /upload and /{module_name}/update
# ---------------------------------------------------------------------------
async def _install_zip_bytes(
    content: bytes,
    filename: str,
    session: Session,
    user,
    allow_update: bool = False,
    signature: Optional[str] = None,
):
    tmpdir = tempfile.mkdtemp(prefix="yads_module_")
    try:
        zip_path = os.path.join(tmpdir, "upload.zip")
        with open(zip_path, "wb") as f:
            f.write(content)

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                names = zf.namelist()
                is_bundle = "bundle_manifest.json" in names
        except zipfile.BadZipFile:
            raise HTTPException(status_code=400, detail="Invalid ZIP file")

        # ----------------------------------------------------------------
        # BUNDLE path
        # ----------------------------------------------------------------
        if is_bundle:
            return await _handle_bundle_upload(content, zip_path, tmpdir, user, session)

        # ----------------------------------------------------------------
        # SINGLE MODULE path
        # ----------------------------------------------------------------
        if not signature:
            signature = sign_zip(content)
        verify_module_signature(content, signature)

        with zipfile.ZipFile(zip_path, "r") as zf:
            resolved_tmp = os.path.realpath(tmpdir)
            for member in zf.namelist():
                member_path = os.path.realpath(os.path.join(tmpdir, member))
                if not member_path.startswith(resolved_tmp + os.sep):
                    raise HTTPException(
                        status_code=400,
                        detail=f"Malicious ZIP: path traversal in member '{member}'"
                    )
            zf.extractall(tmpdir)

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

        if module_name in REGISTRY and not allow_update:
            raise HTTPException(status_code=409, detail=f"Module '{module_name}' already exists in registry")

        existing_installed = session.exec(
            select(InstalledModule).where(InstalledModule.module_name == module_name)
        ).first()
        if existing_installed and existing_installed.is_active and not allow_update:
            raise HTTPException(status_code=409, detail=f"Module '{module_name}' is already installed")

        for setup_file in ["setup.py", "setup.sh"]:
            if os.path.exists(os.path.join(tmpdir, setup_file)):
                raise HTTPException(
                    status_code=400,
                    detail=f"Module ZIP must not contain '{setup_file}'. "
                           "Setup scripts are not executed for security reasons."
                )

        module_file = manifest["module_file"]
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
        im.passive = manifest.get("passive", True)
        im.installed_at = datetime.utcnow()
        im.installed_by = user.id
        im.is_active = True
        im.setup_log = None
        im.signature = signature
        im.file_hash = compute_file_hash(dest)

        session.add(im)
        session.commit()
        session.refresh(im)

        tenants_all = session.exec(select(Tenant)).all()
        for _t in tenants_all:
            _existing_cfg = session.exec(
                select(TenantModuleConfig).where(
                    TenantModuleConfig.tenant_id == _t.id,
                    TenantModuleConfig.module_name == module_name,
                )
            ).first()
            if not _existing_cfg:
                session.add(TenantModuleConfig(tenant_id=_t.id, module_name=module_name, enabled=False))
        session.commit()

        _register_installed_module(im)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return RedirectResponse("/addons/?installed=1", status_code=303)


# ---------------------------------------------------------------------------
# POST /addons/upload — install new add-on from ZIP or bundle (platform admin)
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
    content = await module_zip.read()
    return await _install_zip_bytes(content, module_zip.filename, session, user, allow_update=False, signature=signature)


async def _handle_bundle_upload(
    bundle_content: bytes,
    zip_path: str,
    tmpdir: str,
    user: User,
    session: Session,
):
    """Process a bundle ZIP: install each modules/*.zip, cache store_catalog.json."""
    installed = []
    errors = []

    with zipfile.ZipFile(zip_path, "r") as outer_zf:
        # Zip slip protection on outer bundle
        resolved_tmp = os.path.realpath(tmpdir)
        for member in outer_zf.namelist():
            member_path = os.path.realpath(os.path.join(tmpdir, member))
            if not member_path.startswith(resolved_tmp + os.sep):
                raise HTTPException(
                    status_code=400,
                    detail=f"Malicious bundle ZIP: path traversal in member '{member}'"
                )

        with outer_zf.open("bundle_manifest.json") as bm:
            bundle_manifest = json.load(bm)

        # Cache store_catalog.json if present
        if "store_catalog.json" in outer_zf.namelist():
            with outer_zf.open("store_catalog.json") as sc:
                catalog_data = sc.read().decode("utf-8")
            existing_cfg = session.get(SystemConfig, _CATALOG_DB_KEY)
            if existing_cfg:
                existing_cfg.value = catalog_data
                session.add(existing_cfg)
            else:
                session.add(SystemConfig(key=_CATALOG_DB_KEY, value=catalog_data))
            session.commit()

        # Extract and install each module ZIP
        module_entries = bundle_manifest.get("modules", [])
        for entry in module_entries:
            zip_file_path = entry.get("zip_file", "")
            if not zip_file_path or zip_file_path not in outer_zf.namelist():
                errors.append(f"Missing module zip in bundle: {zip_file_path}")
                continue

            mod_tmpdir = tempfile.mkdtemp(prefix="yads_bundle_mod_")
            try:
                # Extract inner zip
                inner_zip_data = outer_zf.read(zip_file_path)
                inner_zip_path = os.path.join(mod_tmpdir, "module.zip")
                with open(inner_zip_path, "wb") as f:
                    f.write(inner_zip_data)

                # Check inner zip
                try:
                    with zipfile.ZipFile(inner_zip_path, "r") as inner_zf:
                        inner_names = inner_zf.namelist()
                        if "module_manifest.json" not in inner_names:
                            errors.append(f"No module_manifest.json in {zip_file_path}")
                            continue
                        # Zip slip protection for inner zip
                        resolved_mod_tmp = os.path.realpath(mod_tmpdir)
                        for member in inner_names:
                            mp = os.path.realpath(os.path.join(mod_tmpdir, member))
                            if not mp.startswith(resolved_mod_tmp + os.sep):
                                errors.append(f"Path traversal in inner zip {zip_file_path}: {member}")
                                continue
                        inner_zf.extractall(mod_tmpdir)
                except zipfile.BadZipFile:
                    errors.append(f"Invalid ZIP in bundle: {zip_file_path}")
                    continue

                # Sign and install
                inner_sig = sign_zip(inner_zip_data)
                try:
                    verify_module_signature(inner_zip_data, inner_sig)
                except Exception:
                    # If signing is disabled/no key, proceed without sig check
                    inner_sig = None

                # Read manifest and install
                mod_manifest_path = os.path.join(mod_tmpdir, "module_manifest.json")
                with open(mod_manifest_path) as f:
                    mod_manifest = json.load(f)

                module_name = mod_manifest.get("module_name", "")
                _IDENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,63}$')
                if not module_name or not _IDENT_RE.match(module_name):
                    errors.append(f"Invalid module_name in {zip_file_path}: '{module_name}'")
                    continue

                if module_name in REGISTRY:
                    errors.append(f"Skipped '{module_name}': conflicts with built-in registry module")
                    continue

                module_file = mod_manifest.get("module_file", "")
                if (not module_file or os.sep in module_file or "/" in module_file
                        or not module_file.endswith(".py") or module_file.startswith(".")):
                    errors.append(f"Invalid module_file in {zip_file_path}: '{module_file}'")
                    continue

                src = os.path.join(mod_tmpdir, module_file)
                if not os.path.exists(src):
                    errors.append(f"Module file '{module_file}' not found in {zip_file_path}")
                    continue

                # Check for setup scripts
                bad = False
                for setup_file in ["setup.py", "setup.sh"]:
                    if os.path.exists(os.path.join(mod_tmpdir, setup_file)):
                        errors.append(f"Rejected {zip_file_path}: contains '{setup_file}'")
                        bad = True
                        break
                if bad:
                    continue

                os.makedirs(_CUSTOM_MODULES_DIR, exist_ok=True)
                dest = os.path.join(_CUSTOM_MODULES_DIR, module_file)
                shutil.copy2(src, dest)

                module_path = f"yads.modules.custom.{module_file.replace('.py', '')}:{mod_manifest['class_name']}"

                existing_installed = session.exec(
                    select(InstalledModule).where(InstalledModule.module_name == module_name)
                ).first()
                is_update = existing_installed and existing_installed.is_active

                im = existing_installed or InstalledModule()
                im.module_name = module_name
                im.label = mod_manifest.get("label", module_name)
                im.label_de = mod_manifest.get("label_de", mod_manifest.get("label", module_name))
                im.category = mod_manifest.get("category", "active")
                im.version = mod_manifest.get("version", "1.0.0")
                im.author = mod_manifest.get("author", "")
                im.description = mod_manifest.get("description", "")
                im.module_path = module_path
                im.requires_http = mod_manifest.get("requires_http", False)
                im.requires_https = mod_manifest.get("requires_https", False)
                im.default_on = mod_manifest.get("default_on", False)
                im.finding_module = mod_manifest.get("finding_module", True)
                im.extractor = mod_manifest.get("extractor", "generic")
                im.passive = mod_manifest.get("passive", True)
                im.installed_at = datetime.utcnow()
                im.installed_by = user.id
                im.is_active = True
                im.setup_log = None
                im.signature = inner_sig
                im.file_hash = compute_file_hash(dest)

                session.add(im)
                session.commit()
                session.refresh(im)

                tenants_all = session.exec(select(Tenant)).all()
                for _t in tenants_all:
                    _existing_cfg = session.exec(
                        select(TenantModuleConfig).where(
                            TenantModuleConfig.tenant_id == _t.id,
                            TenantModuleConfig.module_name == module_name,
                        )
                    ).first()
                    if not _existing_cfg:
                        session.add(TenantModuleConfig(tenant_id=_t.id, module_name=module_name, enabled=False))
                session.commit()

                _register_installed_module(im)

                installed.append({
                    "module_name": module_name,
                    "label": im.label,
                    "version": im.version,
                    "updated": is_update,
                })
            except HTTPException:
                errors.append(f"Failed to install {zip_file_path}")
            except Exception as exc:
                errors.append(f"Error installing {zip_file_path}: {str(exc)[:120]}")
            finally:
                shutil.rmtree(mod_tmpdir, ignore_errors=True)

    # Return a JSON summary for bundles (client shows it)
    return JSONResponse({
        "bundle": True,
        "bundle_version": bundle_manifest.get("bundle_version", ""),
        "installed": installed,
        "errors": errors,
        "total_installed": len(installed),
        "total_errors": len(errors),
    })


# ---------------------------------------------------------------------------
# POST /addons/{module_name}/delete — remove custom add-on (platform admin)
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

    if module_name in REGISTRY:
        del REGISTRY[module_name]

    configs = session.exec(
        select(TenantModuleConfig).where(TenantModuleConfig.module_name == module_name)
    ).all()
    for cfg in configs:
        session.delete(cfg)

    session.commit()
    return RedirectResponse("/addons/", status_code=303)


# ---------------------------------------------------------------------------
# POST /addons/{module_name}/update — download latest from catalog & re-install
# ---------------------------------------------------------------------------
@router.post("/{module_name}/update")
async def update_module(
    module_name: str,
    session: Session = Depends(get_session),
    user: User = Depends(PlatformAdminChecker()),
):
    catalog = _fetch_catalog(session)
    entry = next((a for a in catalog if a["module_name"] == module_name), None)
    if not entry:
        raise HTTPException(status_code=404, detail="Module not found in catalog")
    download_url = entry.get("download_url")
    if not download_url:
        raise HTTPException(status_code=400, detail="No download URL in catalog for this module")

    try:
        import httpx as _httpx
        with _httpx.Client(timeout=30, follow_redirects=True) as client:
            resp = client.get(download_url)
            resp.raise_for_status()
            zip_bytes = resp.content

            # Try to fetch the accompanying .sig file (YADS official signature)
            sig_url = download_url.rsplit(".zip", 1)[0] + ".sig"
            catalog_signature: Optional[str] = None
            try:
                sig_resp = client.get(sig_url)
                if sig_resp.status_code == 200:
                    catalog_signature = sig_resp.text.strip()
            except Exception:
                pass  # No sig file — fall back to auto-sign
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Download fehlgeschlagen: {e}")

    return await _install_zip_bytes(
        zip_bytes, f"{module_name}.zip", session, user,
        allow_update=True, signature=catalog_signature,
    )


# ---------------------------------------------------------------------------
# POST /addons/update-all — update every installed module that has a newer
#                           version in the catalog
# ---------------------------------------------------------------------------
@router.post("/update-all")
async def update_all_modules(
    session: Session = Depends(get_session),
    user: User = Depends(PlatformAdminChecker()),
):
    catalog = _fetch_catalog(session)
    catalog_map = {a["module_name"]: a for a in catalog}

    installed = session.exec(select(InstalledModule).where(InstalledModule.is_active == True)).all()

    updated, skipped, errors = [], [], []

    import httpx as _httpx
    with _httpx.Client(timeout=30, follow_redirects=True) as client:
        for im in installed:
            entry = catalog_map.get(im.module_name)
            if not entry:
                skipped.append(im.module_name)
                continue
            if not _version_gt(entry.get("version", "0.0.0"), im.version):
                skipped.append(im.module_name)
                continue

            download_url = entry.get("download_url")
            if not download_url:
                errors.append({"module_name": im.module_name, "error": "No download URL in catalog"})
                continue

            try:
                resp = client.get(download_url)
                resp.raise_for_status()
                zip_bytes = resp.content

                sig_url = download_url.rsplit(".zip", 1)[0] + ".sig"
                catalog_signature: Optional[str] = None
                try:
                    sig_resp = client.get(sig_url)
                    if sig_resp.status_code == 200:
                        catalog_signature = sig_resp.text.strip()
                except Exception:
                    pass

                result = await _install_zip_bytes(
                    zip_bytes, f"{im.module_name}.zip", session, user,
                    allow_update=True, signature=catalog_signature,
                )
                updated.append({
                    "module_name": im.module_name,
                    "label": im.label,
                    "from_version": im.version,
                    "to_version": entry.get("version"),
                })
            except HTTPException as e:
                errors.append({"module_name": im.module_name, "error": e.detail})
            except Exception as e:
                errors.append({"module_name": im.module_name, "error": str(e)[:120]})

    return JSONResponse({
        "updated": updated,
        "skipped_count": len(skipped),
        "errors": errors,
        "total_updated": len(updated),
    })


# ---------------------------------------------------------------------------
# GET /addons/catalog — return store catalog JSON
# ---------------------------------------------------------------------------
@router.get("/catalog")
async def get_catalog(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(PlatformAdminChecker()),
):
    catalog = _fetch_catalog(session)
    return JSONResponse({"addons": catalog, "count": len(catalog)})


# ---------------------------------------------------------------------------
# POST /addons/check-updates — compare installed vs catalog
# ---------------------------------------------------------------------------
@router.post("/check-updates")
async def check_updates(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(PlatformAdminChecker()),
):
    catalog = _fetch_catalog(session)
    catalog_map = {a["module_name"]: a.get("version", "0.0.0") for a in catalog}

    installed = session.exec(select(InstalledModule).where(InstalledModule.is_active == True)).all()

    results = []
    for im in installed:
        latest = catalog_map.get(im.module_name)
        if latest:
            results.append({
                "module_name": im.module_name,
                "label": im.label,
                "installed_version": im.version,
                "latest_version": latest,
                "update_available": _version_gt(latest, im.version),
            })

    return JSONResponse({"updates": results, "checked": len(results)})


# ---------------------------------------------------------------------------
# Version comparison helper
# ---------------------------------------------------------------------------
def _version_gt(a: str, b: str) -> bool:
    """Return True if version a > version b (simple semver comparison)."""
    try:
        def _parts(v):
            return [int(x) for x in re.split(r'[.\-]', v) if x.isdigit()]
        return _parts(a) > _parts(b)
    except Exception:
        return False
