# Implementation Plan: Add-On Plugin Persistence Architecture

## Goal Description
The standard YADS distribution is deployed entirely via Docker. Currently, YADS has a secure, signature-validated upload endpoint (`/scan-modules/upload`) that allows administrators to upload custom modules. However, these modules are saved to the container's physical filesystem (`/app/yads/modules/custom/`). When the Docker images are wiped/upgraded, the physical files are deleted, but the PostgreSQL `InstalledModule` record survives. This causes execution/import crashes upon reboot.
Additionally, the recently developed Module Builder packages `.pyz` files, which are incompatible with the existing Uploader's structural requirement (`.zip` with a `module_manifest.json`).

This plan outlines the architecture to make Add-On modules 100% resilient to Docker wipes, correctly formatted, and easily manageable by the Administrator during upgrades.

## Proposed Changes

### [Component] Automation Scripts
#### [MODIFY] [yads-tools/tools/build_modules_pyz.py](file:///home/mrmarco/Documents/gitlab/yads-tools/tools/build_modules_pyz.py)
- **Manifest Auto-Generation:** Refactor the generator. Instead of compiling a `.pyz`, the script will package standard `.zip` files. For each module, it will inject a generated `module_manifest.json` by dynamically importing the script or using default fallbacks (e.g. `module_name`, `class_name`, `label`).
- **Compatibility:** This ensures every module built by the Release Manager can be seamlessly uploaded using the existing YADS UI Plugin Manager.

### [Component] Architecture & Deployment
#### [MODIFY] [yads-infra/docker-compose.yml](file:///home/mrmarco/Documents/gitlab/yads-infra/docker-compose.yml)
- **Volume Mounts**: Add a dedicated named volume for custom modules to both the `yads-api` and `yads-worker` containers:
  - `- yads_custom_modules:/app/yads/modules/custom`
- **Persistence**: This solves the wipe bug natively. Custom `.py` files will securely reside outside the ephemeral container layer and reliably survive image transitions.

### [Component] Core Module Registry Loader
#### [MODIFY] [yads/api/routers/scan_modules.py](file:///home/mrmarco/Documents/gitlab/yads/yads/api/routers/scan_modules.py)
- **Auto-Detection & Recovery Logic**: Update `load_installed_modules_from_db()` (called on fastAPI boot). As it loops through active `InstalledModule` records from Postgres:
  - It will perform an `os.path.exists()` check against the specific custom module physical file.
  - **If Missing (Docker Wiped w/o Volume)**: It sets `im.is_active = False` in the database and logs a warning, rather than blindly importing it into `REGISTRY` (which causes 500 crashes).
- **Admin Alert UI**: Pass a flag to the `scan_modules.html` template when an `InstalledModule` is physically missing. The UI will render a clear "Reactivation Required" badge on the module, prompting the Admin to click "Re-Upload Binaries" to restore it without losing the module's historical configuration or scheduling toggles.

## Verification Plan
- Build modules using the updated Module Builder and verify they contain `module_manifest.json`.
- Upload a custom module to YADS, then physically delete the file to simulate a Docker image wipe. Boot YADS, and verify that it gracefully disables the module without crashing, and clearly prompts the Administrator in the Plugin Settings UI.
- [ ] Execute OSINT Phase 5: Active Scanning Integration
- [ ] Execute OSINT Phase 6: Social Media Identity Expansion
