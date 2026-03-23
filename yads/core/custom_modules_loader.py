import os
from typing import Optional
from sqlmodel import Session, select
from yads.core.module_registry import REGISTRY, ModuleDef
from yads.models import InstalledModule
from yads.core.module_signing import recheck_file_integrity

_CUSTOM_MODULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "modules", "custom"
)

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
        passive=getattr(im, "passive", True),
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
    logger = logging.getLogger("yads.custom_modules_loader")

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

        # Re-verify file integrity against stored SHA-256 hash
        if filepath and not recheck_file_integrity(filepath, im.file_hash, im.module_name):
            logger.critical(
                "Deactivating module '%s' due to integrity violation.",
                im.module_name,
            )
            im.is_active = False
            session.add(im)
            session.commit()
            continue

        _register_installed_module(im)
    
    logger.info(f"Custom scan modules loaded from DB (Total in Registry: {len(REGISTRY)})")
