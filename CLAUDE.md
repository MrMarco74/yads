# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Running the Application

**Docker (Recommended for Development):**
```bash
# Start all services (API, Worker, DB, Redis)
docker-compose up -d

# View logs
docker-compose logs -f yads-api
docker-compose logs -f yads-worker

# Rebuild after code changes
docker-compose up -d --build

# Stop all services
docker-compose down
```

**Manual Python Development:**
```bash
# Install dependencies
pip install -r requirements.txt
playwright install chromium

# Build Tailwind CSS
cd frontend
npm install
npm run build:css

# Run API server (development with hot reload)
uvicorn yads.api.main:app --host 0.0.0.0 --port 8000 --reload

# Run Celery worker in separate terminal
python scripts/start_worker.py

# Run distributed secondary worker (requires MANAGER_URL and token)
WORKER_MODE=secondary MANAGER_URL=http://localhost:8000 \
  WORKER_REGISTRATION_TOKEN=your_token \
  python scripts/start_distributed_worker.py
```

**Docker Swarm Deployment:**
```bash
# Initialize Swarm
docker swarm init

# Label worker nodes
docker node update --label-add yads-worker=true <node-name>

# Deploy stack
docker stack deploy -c docker-compose.swarm.yml yads

# Scale workers
docker service scale yads_yads-worker=5
```

### Database Operations

```bash
# Run migrations (from scripts/maintenance/)
python scripts/maintenance/migrate_db.py

# Reset admin password
python scripts/maintenance/reset_admin_password.py

# Backup database
docker exec yads-api /app/scripts/backup_db.sh

# Access PostgreSQL directly
docker exec -it yads-db psql -U yads -d yads
```

### Frontend Development

```bash
# Watch mode for CSS changes (auto-recompile Tailwind)
cd frontend
npm run watch:css
```

### CI/CD

The `.gitlab-ci.yml` pipeline includes:
- **Lint Stage:** Docker and YAML linting
- **Build Stage:** Multi-stage Docker build, SBOM generation (Syft), CBOM generation
- **Deploy Stage:** Automated deployment to Portainer

```bash
# Build production image locally
docker compose -f docker-compose.prod.yml -f docker-compose.build.yml build yads-api

# Generate SBOM/CBOM
syft . -o cyclonedx-json=sbom.json
python3 scripts/generate_cbom.py
```

## Architecture Overview

### Service Architecture

YADS is a multi-tenant domain intelligence platform with 4 core services:

1. **yads-api** (FastAPI): HTTP API + server-rendered Jinja2 templates
2. **yads-worker** (Celery): Background task execution for scanners
3. **PostgreSQL 15**: Primary data store
4. **Redis 7**: Task queue broker + result backend + real-time logging

**Communication Flow:**
```
User → yads-api → PostgreSQL (data persistence)
              ↓
            Redis (task queue)
              ↓
        yads-worker → Scanner Modules → External Tools (Nuclei, Playwright, Nmap)
              ↓
          PostgreSQL (scan results)
```

### Directory Structure

- **`yads/api/`**: FastAPI application
  - `main.py`: Application entry point with lifespan events (DB migrations, admin seeding)
  - `routers/`: 24 API endpoint modules (auth, analytics, queue, reports, etc.)
  - `templates/`: 59 Jinja2 HTML templates (server-side rendering)
  - `static/`: CSS (Tailwind), JS, screenshots

- **`yads/core/`**: Core business logic
  - `base.py`: `BaseScannerModule` abstract class (all scanners inherit from this)
  - `scheduler.py`: Cron-like scan scheduling (background thread in worker)
  - `backup.py`: Encrypted ZIP backup/restore system
  - `license.py`: Ed25519-based license verification
  - `scoring.py`: Security score calculation (100-point scale)
  - `redis_logger.py`: Real-time log streaming for live UI updates
  - `webhook_service.py`: Event-driven webhook notifications

- **`yads/modules/`**: 19 scanner modules (~5000 lines total)
  - `dns_scanner.py`: DNS records + subdomain enumeration (Certificate Transparency)
  - `web_analyzer.py`: Tech stack detection + CVE lookup (Playwright-based)
  - `ssl_scanner.py`: Certificate analysis
  - `nuclei_scanner.py`: Active vulnerability scanning (ProjectDiscovery Nuclei)
  - `visual_osint.py`: Screenshot capture + OSINT extraction
  - `typosquat_scanner.py`: Brand protection/lookalike domain detection
  - `cloud_scanner.py`: S3 bucket enumeration
  - `crawler.py`: Web spidering
  - `report_generator.py`: PDF report generation

- **`yads/auth/`**: Authentication & authorization
  - JWT tokens (HS256), Bcrypt password hashing
  - TOTP-based MFA (pyotp)
  - RBAC: `admin`, `tenant_admin`, `scanner`, `auditor`

- **`yads/models.py`**: SQLModel database models (14 core models)
  - `Tenant`, `User`, `Target`, `ScanResult`, `ModuleState`, `ChangeEvent`
  - Multi-tenancy via `tenant_id` foreign keys

- **`yads/worker.py`**: Celery worker orchestration (943 lines)
  - Main task: `run_all_scans(target_id, domain, scan_types, tenant_id)`
  - License verification, queue pause checking, subdomain auto-queueing

- **`scripts/`**: Operational scripts
  - `start_worker.py`: Worker startup with DB config loading
  - `maintenance/`: Database migrations, admin password reset
  - `verification/`: Testing scripts for features

- **`frontend/`**: Node.js build system for Tailwind CSS compilation

### Scanner Module Pattern

All scanners extend `BaseScannerModule` (abstract class):

```python
class BaseScannerModule(abc.ABC):
    @property
    @abc.abstractmethod
    def module_name(self) -> str:
        """Unique identifier (e.g., 'dns_scanner')"""

    @abc.abstractmethod
    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        """Execute the scan, return data dict"""

    def compute_hash(self, data: Dict) -> str:
        """SHA256 of deterministic JSON"""

    def process(self, target_id: int, target_domain: str) -> Optional[ScanResult]:
        """Main entry: run scan, check hash, save if changed"""
```

**Change Detection System:**
1. Scanner runs and generates data dict
2. Compute SHA256 hash of sorted JSON
3. Compare with `ModuleState.last_result_hash` for this target/module
4. If hash changed: save `ScanResult` + update `ModuleState`
5. If unchanged: update timestamp only (reduces database bloat)

### Celery Task Flow

**Main Task:** `yads.worker.run_all_scans`

```
1. Verify license from database
2. Check queue pause flag (SystemConfig.QUEUE_ACTIVE)
3. Update target status to "running"
4. Test HTTP/HTTPS connectivity (ports 80/443)
5. Execute selected scanner modules sequentially
   - Each module wrapped in LogCapture context manager
   - Logs streamed to Redis for live UI updates
   - Results saved to PostgreSQL with change detection
6. Auto-queue newly discovered subdomains (if enabled)
7. Update target status to "idle"
8. Fire "scan_finished" webhook event
```

**Real-Time Logging:**
- `RedisLogHandler` publishes logs to Redis lists
- 200-line circular buffer per target
- UI polls Redis for live updates (1-hour TTL)

### Multi-Tenancy

**Isolation:**
- All data scoped by `tenant_id` foreign key
- User-tenant M:N relationship via `UserTenantLink`
- Platform admins have `tenant_id=NULL` and bypass tenant checks

**Quota Management:**
- Per-tenant OSINT quotas tracked in `Tenant.osint_quota_used`
- BYOK (Bring Your Own Key) for external APIs (Google CSE, HIBP)

### Authentication & Authorization

**Security Model:**
- Passwords: Bcrypt via Passlib
- Sessions: JWT tokens (HS256) in HttpOnly cookies
- MFA: TOTP-based with QR code enrollment
- Configurable session timeout (per-tenant overrides)

**Roles:**
- `admin`: Platform admin (full system access, `tenant_id=NULL`)
- `tenant_admin`: Tenant-level admin (user management, settings)
- `scanner`: Can run scans and view results
- `auditor`: Read-only access to scan results

**Dependency Injectors:**
```python
from yads.auth.deps import RoleChecker, PlatformAdminChecker

@router.get("/admin-only")
def admin_route(user: User = Depends(PlatformAdminChecker())):
    # Only platform admins can access
    ...

@router.get("/tenant-admin-route")
def tenant_admin_route(user: User = Depends(RoleChecker(["admin", "tenant_admin"]))):
    # Tenant admins and platform admins can access
    ...
```

### Important Patterns

**1. Null Byte Sanitization:**
PostgreSQL JSONB doesn't support `\u0000` characters. Always use `sanitize_null_bytes()` before database writes:
```python
from yads.utils.sanitize import sanitize_null_bytes
data = sanitize_null_bytes(scan_data)
```

**2. Auto-Queueing:**
Subdomain discovery can auto-queue new targets:
- Controlled by `SystemConfig.AUTO_QUEUE_SUBDOMAINS` flag
- New subdomains inherit parent's `tenant_id`
- Scoped to `dns_scanner` only (prevents recursive explosion)

**3. Queue Pause Mechanism:**
Global stop signal for workers:
- `SystemConfig.QUEUE_ACTIVE` boolean flag
- Worker checks before executing tasks (retry with 60s countdown if paused)
- Toggle via UI without restarting workers

**4. License Verification:**
Ed25519 signature verification on every scan:
- License key stored in `SystemConfig.LICENSE_KEY`
- Payload format: `base64(json_payload).base64(signature)`
- Worker validates before task execution

**5. DNS Cleanup:**
`dns_cleanup_scanner` module marks unresolvable domains:
- Sets `Target.is_archived=true` + `archived_reason`
- Separate UI view for archived targets
- Prevents wasted scans on dead domains

**6. Distributed Workers:**
Horizontal scaling via Docker Swarm:
- `WorkerManager` (`yads/core/worker_manager.py`): Central coordinator
- `WorkerClient` (`yads/core/worker_client.py`): Worker-side communication
- Workers register with pre-shared token, send heartbeats every 30s
- Tasks routed to least-loaded worker with capacity
- Resource quotas enforced per-tenant and globally

### Distributed Worker Architecture

**Components:**
- **`yads/core/worker_manager.py`**: Central coordinator for registration, heartbeat, task routing
- **`yads/core/worker_client.py`**: Worker-side client for manager communication
- **`yads/api/routers/workers.py`**: REST API endpoints for worker management
- **`yads/core/redis_logger.py`**: `DistributedRedisLogHandler` with tenant tagging

**Worker Modes:**
```python
from yads.core.worker_client import WorkerMode

# Modes set via WORKER_MODE environment variable:
# - "standalone": No distributed coordination (default, backwards compatible)
# - "primary": Runs on manager node, uses database directly
# - "secondary": Runs on worker node, communicates via HTTP API
```

**New Database Models:**
```python
from yads.models import WorkerNode, WorkerTask, ResourceQuota

# WorkerNode: Registered worker with status, capabilities, load
# WorkerTask: Task tracking with progress, assigned worker
# ResourceQuota: Per-tenant or global resource limits
```

**Key Configuration:**
| Environment Variable | Description |
|---------------------|-------------|
| `WORKER_MODE` | `standalone`, `primary`, or `secondary` |
| `MANAGER_URL` | Manager API URL (for secondary workers) |
| `WORKER_REGISTRATION_TOKEN` | Pre-shared token for registration |
| `WORKER_MAX_TASKS` | Max concurrent tasks per worker |

**Startup Scripts:**
- `scripts/start_worker.py`: Standard/primary worker startup
- `scripts/start_distributed_worker.py`: Secondary worker with registration

## Key Technologies

- **FastAPI**: Web framework with OpenAPI docs at `/docs`
- **SQLModel**: ORM combining SQLAlchemy + Pydantic
- **Celery**: Distributed task queue
- **Playwright**: Headless browser automation (Chromium)
- **Nuclei**: Vulnerability scanner (ProjectDiscovery v3.3.4)
- **Nmap**: Network port scanning
- **Tailwind CSS 3.4**: Utility-first CSS framework
- **Jinja2**: Server-side templating
- **HTMX**: Dynamic HTML updates (inferred from templates)

## External Integrations

- **Certificate Transparency**: crt.sh API for subdomain enumeration
- **Google Custom Search**: OSINT searches (BYOK model)
- **Wayback Machine**: archive.org CDX API for historical data
- **Have I Been Pwned**: Data breach monitoring (BYOK)
- **Splunk**: SIEM logging (optional)
- **Slack/Teams**: Webhook notifications

## Testing

Tests are minimal in this codebase. The `tests/` directory contains backup files only. Verification scripts in `scripts/verification/` can be used for manual testing:

```bash
# Verify authentication flow
python scripts/verification/verify_auth.py

# Verify queue and logging
python scripts/verification/verify_queue_logs.py

# Verify schedules
python scripts/verification/verify_schedules.py
```

## Database Schema Notes

**Core Tables:**
- `tenant`: Multi-tenancy root, quota management
- `user`: Authentication, RBAC, MFA
- `target`: Domains/assets to scan
- `scanresult`: Scan data (JSONB payload)
- `modulestate`: Last scan hash per module/target (change detection)
- `changeevent`: Specific diffs detected
- `systemconfig`: Key-value runtime configuration
- `scanschedule`: Cron-like scheduling
- `webhook`: Event-driven integrations
- `securitytrend`: Historical security scores
- `httptraffic`: Request/response logs from crawler

**Distributed Worker Tables:**
- `workernode`: Registered workers with status, capabilities, load metrics
- `workertask`: Task tracking with progress, assigned worker, timing
- `resourcequota`: Per-tenant or global resource limits (concurrent scans, daily limits)

**Important Relationships:**
- `Target.tenant_id → Tenant.id` (1:N)
- `User.tenant_id → Tenant.id` (N:1, primary tenant)
- `UserTenantLink` (M:N for cross-tenant access)
- `ScanResult.target_id → Target.id` (N:1)
- `ModuleState` unique on `(target_id, module_name)`
- `WorkerTask.worker_node_id → WorkerNode.id` (N:1)
- `WorkerTask.target_id → Target.id` (N:1)
- `ResourceQuota.tenant_id → Tenant.id` (N:1, NULL for global)

## Common Maintenance Tasks

**Reset Admin Password:**
```bash
python scripts/maintenance/reset_admin_password.py
```

**Update Database Schema:**
The `migrate_db.py` script is run automatically on API startup. Manual execution:
```bash
python scripts/maintenance/migrate_db.py
```

**Cleanup Dead Targets:**
```bash
python scripts/cleanup_dead_targets.py
```

**Queue All DNS Cleanup Scans:**
```bash
python scripts/queue_all_dns_cleanup.py
```

**Generate License Keys:**
```bash
python scripts/generate_license_keys.py
python scripts/sign_license.py
python scripts/apply_license.py
```

## Environment Variables

Key environment variables (set in `docker-compose.yml` or `.env`):

- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `SECRET_KEY`: JWT signing key
- `CHROME_BIN`: Path to Chrome binary (default: `/usr/bin/google-chrome`)
- `LOG_DIR`: Log directory path (default: `/app/logs`)
- `MFA_ENABLED`: Toggle MFA enforcement (default: `false`)
- `CONFIG_PATH`: Persistent config file path

## Deployment

**Production Stack:**
Use `docker-compose.prod.yml` for production:
```bash
docker compose -f docker-compose.prod.yml up -d
```

**Multi-Stage Build Targets:**
- `css-builder`: Compile Tailwind CSS
- `base`: System deps + Python packages + Playwright
- `dev`: Development with hot reload
- `prod`: Standard production (non-compiled)
- `release`: Nuitka-compiled production (experimental)

**Automated Backups:**
The `backup_db.sh` script runs on API startup. Manual backups can be triggered via the UI under **Settings → Backup & Restore**.

## License

MIT License. See `LICENSE`.

## Bug Report References in Git Commits

Bug reports received via **support.yads-security.com** have IDs in the format `YAD-YYYY-NNNNN` (e.g. `YAD-2026-00007`).

**Convention:** When fixing a bug that was reported via the support portal, always include a `Fixes:` trailer in the commit message:

```
fix: short description of the fix

Longer explanation if needed.

Fixes: YAD-2026-00007
Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
```

**For Claude Code:** If the user provides a bug report (inline or via the support portal ID) and you create a fix commit, **always** include `Fixes: YAD-YYYY-NNNNN` in the commit body when the report ID is known. Do not skip this even when the fix is small.

A `commit-msg` git hook warns (non-blocking) if a `fix:` commit is missing this reference.
