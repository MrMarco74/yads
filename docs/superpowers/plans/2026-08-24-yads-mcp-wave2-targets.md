# yads-mcp Wave 2 (Target/Asset Management) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a new API-key-authenticated `/api/v1/targets*` surface to YADS (12 endpoints) covering target listing/detail/add/delete/archive/blocklist/history/status, then expose all 12 as MCP tools in the yads-mcp repo.

**Architecture:** One new router file `yads/api/routers/v1_targets.py`, same shape as `v1_queue.py`/`v1_tags.py`/`v1_scan.py`: `get_api_key`/`RequireScope`/`require_tenant_scoped_key` from `yads/auth/deps.py`, tenant-scoped queries throughout, `destructive` scope + `confirm:bool` on the two irreversible-without-undo operations. Mirrors existing HTML-route logic (`targets.py`, `archived.py`) by import/adaptation, not by touching those routes. Then a fourth tool group in `yads-mcp/yads_mcp/server.py`.

**Tech Stack:** FastAPI, SQLModel, Celery, `httpx`, pytest + Starlette `TestClient` — all unchanged from Wave 1.

**Spec:** `docs/superpowers/specs/2026-08-24-yads-mcp-wave2-targets-design.md` (and Wave 1's foundation spec, `docs/superpowers/specs/2026-08-24-yads-mcp-foundation-design.md`, for the conventions this plan reuses without re-explaining).

## Global Constraints

- Every route uses `require_tenant_scoped_key` (not bare `get_api_key`) — this closes the NULL-tenant fail-open class of bug Wave 1's final review found; there is no reason for any new route to use bare `get_api_key`.
- `bulk_delete_targets` and `bulk_blocklist_targets` are the only two `destructive`-scoped routes, each requiring `RequireScope("destructive")` AND a request-body `confirm: bool` with no Python default, checked server-side with a 400 if false.
- `list_targets`, `get_target`, `get_target_changes`, `get_scan_status`, `get_network_context` require `RequireScope("read")`. `add_target`, `undo_bulk_delete_targets`, `bulk_archive_targets`, `archive_dead_targets`, `restore_target` require `RequireScope("write")`.
- All queries filter by `api_key.tenant_id`, never a client-supplied tenant parameter.
- `list_targets`'s filter set is deliberately curated (tag, online, scan_status, domain_search, archived, last_scanned_before, page, limit) — not the dashboard's 20+ raw UI filters. `limit` capped at 100.
- "Send targets to Discovery", file-based bulk import, and logo upload are explicitly out of scope for this wave (see spec §1).
- Do not modify `targets.py` or `archived.py` — this wave only adds a new router that reuses their patterns/helpers by import where the helper is generic enough (`_get_owned_target_ids`, `_perform_bulk_delete_from_db`), and writes fresh tenant-scoped queries where the existing route's logic is too HTML/session-specific to reuse directly (`list_targets`, `get_target`).

---

### Task 1: `v1_targets.py` — `list_targets` and `get_target`

**Files:**
- Create: `yads/api/routers/v1_targets.py`
- Test: `tests/test_v1_targets_read.py`

**Interfaces:**
- Consumes: `require_tenant_scoped_key`, `RequireScope` (`yads/auth/deps.py`); `get_session` (`yads/database.py`); `Target`, `ScanResult` (`yads/models.py`).
- Produces: `router = APIRouter(prefix="/api/v1", tags=["API v1 — Targets"])` with `GET /api/v1/targets`, `GET /api/v1/targets/{target_id}`. Later tasks in this plan append more routes to this same file.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_v1_targets_read.py
"""Covers GET /api/v1/targets (list) and GET /api/v1/targets/{id} (detail)."""

import pytest


@pytest.fixture
def sample_targets(db_session, test_tenant):
    from yads.models import Target
    from sqlmodel import select

    domains = ["v1-list-fixture-1.example.com", "v1-list-fixture-2.example.com"]
    created = []
    for d in domains:
        existing = db_session.exec(select(Target).where(Target.domain == d, Target.tenant_id == test_tenant.id)).first()
        if existing:
            created.append(existing)
            continue
        t = Target(domain=d, tenant_id=test_tenant.id, tags=["fixture-tag"])
        db_session.add(t)
        db_session.commit()
        db_session.refresh(t)
        created.append(t)
    return created


def test_list_targets_requires_api_key(client):
    r = client.get("/api/v1/targets")
    assert r.status_code == 401


def test_list_targets_returns_shape(api_key_client, sample_targets):
    r = api_key_client.get("/api/v1/targets")
    assert r.status_code == 200
    body = r.json()
    assert "targets" in body
    assert "total" in body
    assert "page" in body


def test_list_targets_filters_by_tag(api_key_client, sample_targets):
    r = api_key_client.get("/api/v1/targets", params={"tag": "fixture-tag"})
    assert r.status_code == 200
    domains = [t["domain"] for t in r.json()["targets"]]
    assert "v1-list-fixture-1.example.com" in domains
    assert "v1-list-fixture-2.example.com" in domains


def test_list_targets_filters_by_domain_search(api_key_client, sample_targets):
    r = api_key_client.get("/api/v1/targets", params={"domain_search": "list-fixture-1"})
    assert r.status_code == 200
    domains = [t["domain"] for t in r.json()["targets"]]
    assert "v1-list-fixture-1.example.com" in domains
    assert "v1-list-fixture-2.example.com" not in domains


def test_get_target_returns_summary(api_key_client, sample_targets):
    target = sample_targets[0]
    r = api_key_client.get(f"/api/v1/targets/{target.id}")
    assert r.status_code == 200
    body = r.json()
    assert body["domain"] == target.domain
    assert "scan_status" in body
    assert "module_count" in body


def test_get_target_other_tenant_returns_404(api_key_client, db_session):
    from yads.models import Target, Tenant
    from sqlmodel import select

    other_tenant = Tenant(name="Other Tenant For Targets Read Test")
    existing = db_session.exec(select(Tenant).where(Tenant.name == other_tenant.name)).first()
    if not existing:
        db_session.add(other_tenant)
        db_session.commit()
        db_session.refresh(other_tenant)
        existing = other_tenant

    other_target = db_session.exec(select(Target).where(Target.domain == "other-tenant-v1-targets-read.example.com")).first()
    if not other_target:
        other_target = Target(domain="other-tenant-v1-targets-read.example.com", tenant_id=existing.id, tags=[])
        db_session.add(other_target)
        db_session.commit()
        db_session.refresh(other_target)

    r = api_key_client.get(f"/api/v1/targets/{other_target.id}")
    assert r.status_code == 404
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_v1_targets_read.py -v`
Expected: FAIL — `ModuleNotFoundError` or connection error, since `yads/api/routers/v1_targets.py` doesn't exist yet.

- [ ] **Step 3: Create the router**

```python
# yads/api/routers/v1_targets.py
"""API-key-authenticated Target/Asset Management surface for yads-mcp and
other machine clients. See
docs/superpowers/specs/2026-08-24-yads-mcp-wave2-targets-design.md.
"""

from datetime import datetime
from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, and_, func, or_, select, text

from yads.auth.deps import RequireScope, require_tenant_scoped_key
from yads.database import get_session
from yads.models import APIKey, ScanResult, Target

router = APIRouter(prefix="/api/v1", tags=["API v1 — Targets"])


@router.get("/targets", dependencies=[Depends(RequireScope("read"))])
async def list_targets(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
    tag: Optional[str] = None,
    online: Optional[bool] = None,
    scan_status: Optional[str] = None,
    domain_search: Optional[str] = None,
    archived: bool = False,
    last_scanned_before: Optional[str] = None,
    page: int = 1,
    limit: int = 20,
):
    limit = min(limit, 100)
    page = max(page, 1)

    query = select(Target).where(
        Target.tenant_id == api_key.tenant_id,
        Target.is_archived == archived,
    )

    if tag:
        query = query.where(Target.tags.contains([tag]))
    if scan_status:
        query = query.where(Target.scan_status == scan_status)
    if domain_search:
        query = query.where(Target.domain.ilike(f"%{domain_search}%"))
    if online is not None:
        online_criteria = or_(
            and_(ScanResult.module_name == "infrastructure_scanner", text("data->>'ip' IS NOT NULL")),
            and_(ScanResult.module_name == "web_analyzer", text("(data->>'status_code')::int > 0")),
            and_(ScanResult.module_name == "port_scanner", text("data->>'is_active' = 'true'")),
        )
        sub_online = select(ScanResult.target_id).where(online_criteria).distinct()
        if online:
            query = query.where(Target.id.in_(sub_online))
        else:
            query = query.where(Target.id.notin_(sub_online))
    if last_scanned_before:
        try:
            cutoff = datetime.fromisoformat(last_scanned_before)
        except ValueError:
            raise HTTPException(status_code=400, detail="last_scanned_before must be an ISO date string")
        sub_recent = select(ScanResult.target_id).where(ScanResult.scanned_at >= cutoff).distinct()
        query = query.where(Target.id.notin_(sub_recent))

    total = session.exec(select(func.count()).select_from(query.subquery())).one()
    rows = session.exec(query.order_by(Target.domain).offset((page - 1) * limit).limit(limit)).all()

    return {
        "targets": [
            {"id": t.id, "domain": t.domain, "scan_status": t.scan_status, "tags": t.tags, "is_archived": t.is_archived, "created_at": t.created_at.isoformat()}
            for t in rows
        ],
        "total": total,
        "page": page,
    }


@router.get("/targets/{target_id}", dependencies=[Depends(RequireScope("read"))])
async def get_target(
    target_id: int,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    target = session.exec(
        select(Target).where(Target.id == target_id, Target.tenant_id == api_key.tenant_id)
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    last_scan_at = session.exec(
        select(func.max(ScanResult.scanned_at)).where(ScanResult.target_id == target_id)
    ).one()
    module_count = session.exec(
        select(func.count(func.distinct(ScanResult.module_name))).where(ScanResult.target_id == target_id)
    ).one()

    return {
        "id": target.id,
        "domain": target.domain,
        "scan_status": target.scan_status,
        "scan_progress": target.scan_progress,
        "tags": target.tags,
        "is_archived": target.is_archived,
        "archived_reason": target.archived_reason,
        "created_at": target.created_at.isoformat(),
        "last_scan_at": last_scan_at.isoformat() if last_scan_at else None,
        "module_count": module_count,
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_v1_targets_read.py -v`
Expected: FAIL with `404 Not Found` on every route — the router isn't registered in `main.py` yet (Task 8's job, same red-until-registered pattern as Wave 1). No import errors, no 500s. This is the expected outcome for this task; proceed to commit.

- [ ] **Step 5: Commit**

```bash
git add yads/api/routers/v1_targets.py tests/test_v1_targets_read.py
git commit -m "feat: add API-key-authenticated list_targets/get_target endpoints"
```

---

### Task 2: `v1_targets.py` — `add_target`

**Files:**
- Modify: `yads/api/routers/v1_targets.py`
- Test: `tests/test_v1_targets_add.py`

**Interfaces:**
- Consumes: `_is_internal_target` (`yads/api/routers/targets.py`, module-level SSRF-guard function — import it, don't duplicate).
- Produces: `POST /api/v1/targets` on the same router.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_v1_targets_add.py
"""Covers POST /api/v1/targets (add a single target)."""


def test_add_target_creates_new(api_key_client):
    r = api_key_client.post("/api/v1/targets", json={"domain": "v1-add-fixture.example.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["domain"] == "v1-add-fixture.example.com"
    assert "id" in body


def test_add_target_is_idempotent_find_or_create(api_key_client):
    r1 = api_key_client.post("/api/v1/targets", json={"domain": "v1-add-idempotent.example.com"})
    r2 = api_key_client.post("/api/v1/targets", json={"domain": "v1-add-idempotent.example.com"})
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json()["id"] == r2.json()["id"]


def test_add_target_blocks_internal_domain(api_key_client):
    r = api_key_client.post("/api/v1/targets", json={"domain": "localhost"})
    assert r.status_code == 400
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_v1_targets_add.py -v`
Expected: FAIL with `404 Not Found` (route doesn't exist in this file yet).

- [ ] **Step 3: Add the endpoint**

Add this import to the top of `yads/api/routers/v1_targets.py` (alongside Task 1's imports):

```python
from yads.api.routers.targets import _is_internal_target
```

Append to `yads/api/routers/v1_targets.py`:

```python
class AddTargetRequest(BaseModel):
    domain: str


@router.post("/targets", dependencies=[Depends(RequireScope("write"))])
async def add_target(
    payload: AddTargetRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    domain = payload.domain.lower().strip()
    if _is_internal_target(domain):
        raise HTTPException(status_code=400, detail="Internal targets blocked by SSRF protection")

    existing = session.exec(
        select(Target).where(Target.domain == domain, Target.tenant_id == api_key.tenant_id)
    ).first()
    if existing:
        return {"id": existing.id, "domain": existing.domain, "created": False}

    target = Target(domain=domain, tenant_id=api_key.tenant_id)
    session.add(target)
    session.commit()
    session.refresh(target)
    return {"id": target.id, "domain": target.domain, "created": True}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_v1_targets_add.py -v`
Expected: FAIL with `404 Not Found` until Task 8 registers the router. Proceed to commit.

- [ ] **Step 5: Commit**

```bash
git add yads/api/routers/v1_targets.py tests/test_v1_targets_add.py
git commit -m "feat: add API-key-authenticated add_target endpoint"
```

---

### Task 3: `v1_targets.py` — `bulk_delete_targets` + `undo_bulk_delete_targets`

**Files:**
- Modify: `yads/api/routers/v1_targets.py`
- Test: `tests/test_v1_targets_delete.py`

**Interfaces:**
- Consumes: `_get_owned_target_ids`, `_perform_bulk_delete_from_db` (`yads/api/routers/targets.py`, module-level helpers — import, don't duplicate); `celery_app` (`yads/worker.py`); `redis_client` (`yads/database.py`).
- Produces: `POST /api/v1/targets/bulk-delete`, `POST /api/v1/targets/bulk-delete/undo` on the same router.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_v1_targets_delete.py
"""Covers POST /api/v1/targets/bulk-delete and its undo companion."""

import pytest


@pytest.fixture
def deletable_targets(db_session, test_tenant):
    from yads.models import Target
    from sqlmodel import select

    domains = ["v1-delete-fixture-1.example.com", "v1-delete-fixture-2.example.com"]
    created = []
    for d in domains:
        existing = db_session.exec(select(Target).where(Target.domain == d, Target.tenant_id == test_tenant.id)).first()
        if existing:
            created.append(existing)
            continue
        t = Target(domain=d, tenant_id=test_tenant.id, tags=[])
        db_session.add(t)
        db_session.commit()
        db_session.refresh(t)
        created.append(t)
    return created


def test_bulk_delete_requires_confirm(api_key_client, deletable_targets):
    ids = [t.id for t in deletable_targets]
    r = api_key_client.post("/api/v1/targets/bulk-delete", json={"target_ids": ids, "confirm": False})
    assert r.status_code == 400


def test_bulk_delete_requires_destructive_scope(client, db_session, test_tenant, deletable_targets):
    from yads.models import APIKey
    from yads.auth.security import generate_api_key

    plain_key, prefix, key_hash = generate_api_key()
    key_row = APIKey(
        tenant_id=test_tenant.id, name="pytest-no-destructive-targets",
        key_prefix=prefix, key_hash=key_hash, scopes=["read", "write"],
    )
    db_session.add(key_row)
    db_session.commit()

    ids = [t.id for t in deletable_targets]
    r = client.post("/api/v1/targets/bulk-delete", json={"target_ids": ids, "confirm": True}, headers={"X-API-Key": plain_key})
    assert r.status_code == 403


def test_bulk_delete_and_undo(api_key_client, db_session, test_tenant):
    from yads.models import Target
    from sqlmodel import select

    domain = "v1-delete-and-undo-fixture.example.com"
    existing = db_session.exec(select(Target).where(Target.domain == domain, Target.tenant_id == test_tenant.id)).first()
    if not existing:
        existing = Target(domain=domain, tenant_id=test_tenant.id, tags=["keep-me"])
        db_session.add(existing)
        db_session.commit()
        db_session.refresh(existing)
    target_id = existing.id

    r = api_key_client.post("/api/v1/targets/bulk-delete", json={"target_ids": [target_id], "confirm": True})
    assert r.status_code == 200
    body = r.json()
    assert body["deleted_count"] == 1
    assert body["undo_batch"]

    gone = db_session.exec(select(Target).where(Target.id == target_id)).first()
    assert gone is None

    r2 = api_key_client.post("/api/v1/targets/bulk-delete/undo", json={"undo_batch": body["undo_batch"]})
    assert r2.status_code == 200
    assert r2.json()["restored_count"] == 1

    restored = db_session.exec(select(Target).where(Target.domain == domain, Target.tenant_id == test_tenant.id)).first()
    assert restored is not None
    assert restored.tags == ["keep-me"]


def test_undo_bulk_delete_expired_batch_returns_404(api_key_client):
    r = api_key_client.post("/api/v1/targets/bulk-delete/undo", json={"undo_batch": "nonexistent-batch"})
    assert r.status_code == 404
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_v1_targets_delete.py -v`
Expected: FAIL with `404 Not Found` on every route.

- [ ] **Step 3: Add the endpoints**

Add these imports to the top of `yads/api/routers/v1_targets.py` (alongside Tasks 1-2's imports):

```python
import json
import uuid as _uuid

from yads.api.routers.targets import _get_owned_target_ids, _perform_bulk_delete_from_db
from yads.database import redis_client
from yads.worker import celery_app
```

Append to `yads/api/routers/v1_targets.py`:

```python
class BulkDeleteRequest(BaseModel):
    target_ids: List[int]
    confirm: bool


@router.post("/targets/bulk-delete", dependencies=[Depends(RequireScope("destructive"))])
async def bulk_delete_targets(
    payload: BulkDeleteRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    if not payload.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to delete these targets")
    if not payload.target_ids:
        raise HTTPException(status_code=400, detail="No target_ids provided")

    ids_to_delete = set(payload.target_ids)

    revoked_count = 0
    i = celery_app.control.inspect(timeout=5.0)
    if i:
        for tasks in list((i.active() or {}).values()) + list((i.reserved() or {}).values()):
            for task in tasks:
                args = task.get("args", [])
                if args and isinstance(args, list) and len(args) > 0:
                    try:
                        if int(args[0]) in ids_to_delete:
                            celery_app.control.revoke(task.get("id"), terminate=True)
                            revoked_count += 1
                    except Exception:
                        continue

    class _ApiKeyAsUser:
        def __init__(self, tenant_id):
            self.tenant_id = tenant_id

    fake_user = _ApiKeyAsUser(tenant_id=api_key.tenant_id)
    safe_ids = _get_owned_target_ids(session, fake_user, ids_to_delete)
    if not safe_ids:
        raise HTTPException(status_code=404, detail="No owned targets found")

    targets_to_delete = session.exec(select(Target).where(Target.id.in_(safe_ids))).all()
    snapshot = [
        {"domain": t.domain, "tenant_id": t.tenant_id, "tags": t.tags, "discovery_reason": t.discovery_reason}
        for t in targets_to_delete
    ]
    undo_batch_id = _uuid.uuid4().hex[:12]
    redis_client.setex(f"yads:undo_delete:{undo_batch_id}", 60, json.dumps(snapshot))

    _perform_bulk_delete_from_db(session, safe_ids)
    session.commit()

    return {"deleted_count": len(safe_ids), "revoked_count": revoked_count, "undo_batch": undo_batch_id}


class UndoDeleteRequest(BaseModel):
    undo_batch: str


@router.post("/targets/bulk-delete/undo", dependencies=[Depends(RequireScope("write"))])
async def undo_bulk_delete_targets(
    payload: UndoDeleteRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    key = f"yads:undo_delete:{payload.undo_batch}"
    raw = redis_client.get(key)
    if not raw:
        raise HTTPException(status_code=404, detail="Undo window expired or batch not found")

    snapshot = json.loads(raw)
    restored = 0
    for entry in snapshot:
        if entry.get("tenant_id") != api_key.tenant_id:
            continue
        existing = session.exec(
            select(Target).where(Target.domain == entry["domain"], Target.tenant_id == entry["tenant_id"])
        ).first()
        if existing:
            continue
        session.add(Target(
            domain=entry["domain"], tenant_id=entry["tenant_id"],
            tags=entry.get("tags"), discovery_reason=entry.get("discovery_reason"),
        ))
        restored += 1
    session.commit()
    redis_client.delete(key)

    return {"restored_count": restored}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_v1_targets_delete.py -v`
Expected: FAIL with `404 Not Found` until Task 8 registers the router. Proceed to commit.

- [ ] **Step 5: Commit**

```bash
git add yads/api/routers/v1_targets.py tests/test_v1_targets_delete.py
git commit -m "feat: add destructive-scoped bulk_delete_targets + undo endpoints"
```

---

### Task 4: `v1_targets.py` — `bulk_archive_targets`, `archive_dead_targets`, `restore_target`

**Files:**
- Modify: `yads/api/routers/v1_targets.py`
- Test: `tests/test_v1_targets_archive.py`

**Interfaces:**
- Consumes: nothing new beyond Tasks 1-3's imports.
- Produces: `POST /api/v1/targets/bulk-archive`, `POST /api/v1/targets/archive-dead`, `POST /api/v1/targets/{target_id}/restore` on the same router.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_v1_targets_archive.py
"""Covers bulk-archive, archive-dead, and restore endpoints."""

import pytest


@pytest.fixture
def archivable_target(db_session, test_tenant):
    from yads.models import Target
    from sqlmodel import select

    domain = "v1-archive-fixture.example.com"
    existing = db_session.exec(select(Target).where(Target.domain == domain, Target.tenant_id == test_tenant.id)).first()
    if existing:
        return existing
    t = Target(domain=domain, tenant_id=test_tenant.id, tags=[])
    db_session.add(t)
    db_session.commit()
    db_session.refresh(t)
    return t


def test_bulk_archive_and_restore(api_key_client, archivable_target, db_session):
    from yads.models import Target
    from sqlmodel import select

    r = api_key_client.post("/api/v1/targets/bulk-archive", json={"target_ids": [archivable_target.id]})
    assert r.status_code == 200
    assert r.json()["archived_count"] == 1

    db_session.refresh(archivable_target)
    assert archivable_target.is_archived is True
    assert archivable_target.archived_reason == "manual"

    r2 = api_key_client.post(f"/api/v1/targets/{archivable_target.id}/restore")
    assert r2.status_code == 200

    db_session.refresh(archivable_target)
    assert archivable_target.is_archived is False
    assert archivable_target.archived_reason is None


def test_archive_dead_targets_returns_count(api_key_client):
    r = api_key_client.post("/api/v1/targets/archive-dead")
    assert r.status_code == 200
    assert "archived_count" in r.json()


def test_restore_nonexistent_target_returns_404(api_key_client):
    r = api_key_client.post("/api/v1/targets/999999999/restore")
    assert r.status_code == 404
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_v1_targets_archive.py -v`
Expected: FAIL with `404 Not Found` on every route.

- [ ] **Step 3: Add the endpoints**

Append to `yads/api/routers/v1_targets.py`:

```python
class BulkArchiveRequest(BaseModel):
    target_ids: List[int]


@router.post("/targets/bulk-archive", dependencies=[Depends(RequireScope("write"))])
async def bulk_archive_targets(
    payload: BulkArchiveRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    if not payload.target_ids:
        raise HTTPException(status_code=400, detail="No target_ids provided")

    owned_targets = session.exec(
        select(Target).where(
            Target.id.in_(set(payload.target_ids)),
            Target.tenant_id == api_key.tenant_id,
            Target.is_archived == False,
        )
    ).all()

    count = 0
    for target in owned_targets:
        target.is_archived = True
        target.archived_at = datetime.utcnow()
        target.archived_reason = "manual"
        session.add(target)
        count += 1
    session.commit()

    return {"archived_count": count}


@router.post("/targets/archive-dead", dependencies=[Depends(RequireScope("write"))])
async def archive_dead_targets(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    subquery = text("""
        SELECT t.id FROM target t
        JOIN LATERAL (
            SELECT data FROM scanresult
            WHERE target_id = t.id AND module_name = 'dns_scanner'
            ORDER BY scanned_at DESC LIMIT 1
        ) sr ON true
        WHERE (sr.data->'records')::text = '{}'
        AND t.is_archived = false
        AND t.tenant_id = :tenant_id
    """)
    dead_ids = [row[0] for row in session.exec(subquery.bindparams(tenant_id=api_key.tenant_id)).all()]

    count = 0
    if dead_ids:
        targets = session.exec(select(Target).where(Target.id.in_(dead_ids))).all()
        for target in targets:
            target.is_archived = True
            target.archived_at = datetime.utcnow()
            target.archived_reason = "DNS cleanup: empty records"
            session.add(target)
            count += 1
        session.commit()

    return {"archived_count": count}


@router.post("/targets/{target_id}/restore", dependencies=[Depends(RequireScope("write"))])
async def restore_target(
    target_id: int,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    target = session.exec(
        select(Target).where(Target.id == target_id, Target.tenant_id == api_key.tenant_id)
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    target.is_archived = False
    target.archived_at = None
    target.archived_reason = None
    session.add(target)
    session.commit()

    return {"id": target.id, "domain": target.domain, "is_archived": target.is_archived}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_v1_targets_archive.py -v`
Expected: FAIL with `404 Not Found` until Task 8 registers the router. Proceed to commit.

- [ ] **Step 5: Commit**

```bash
git add yads/api/routers/v1_targets.py tests/test_v1_targets_archive.py
git commit -m "feat: add bulk_archive_targets, archive_dead_targets, restore_target endpoints"
```

---

### Task 5: `v1_targets.py` — `bulk_blocklist_targets`

**Files:**
- Modify: `yads/api/routers/v1_targets.py`
- Test: `tests/test_v1_targets_blocklist.py`

**Interfaces:**
- Consumes: `DiscoveryDomainBlocklist` (`yads/models.py`).
- Produces: `POST /api/v1/targets/bulk-blocklist` on the same router.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_v1_targets_blocklist.py
"""Covers POST /api/v1/targets/bulk-blocklist -- destructive (archives +
adds an exact-match blocklist pattern, no single-action undo)."""

import pytest


@pytest.fixture
def blocklistable_target(db_session, test_tenant):
    from yads.models import Target
    from sqlmodel import select

    domain = "v1-blocklist-fixture.example.com"
    existing = db_session.exec(select(Target).where(Target.domain == domain, Target.tenant_id == test_tenant.id)).first()
    if existing:
        return existing
    t = Target(domain=domain, tenant_id=test_tenant.id, tags=[])
    db_session.add(t)
    db_session.commit()
    db_session.refresh(t)
    return t


def test_bulk_blocklist_requires_confirm(api_key_client, blocklistable_target):
    r = api_key_client.post("/api/v1/targets/bulk-blocklist", json={"target_ids": [blocklistable_target.id], "confirm": False})
    assert r.status_code == 400


def test_bulk_blocklist_requires_destructive_scope(client, db_session, test_tenant, blocklistable_target):
    from yads.models import APIKey
    from yads.auth.security import generate_api_key

    plain_key, prefix, key_hash = generate_api_key()
    key_row = APIKey(
        tenant_id=test_tenant.id, name="pytest-no-destructive-blocklist",
        key_prefix=prefix, key_hash=key_hash, scopes=["read", "write"],
    )
    db_session.add(key_row)
    db_session.commit()

    r = client.post(
        "/api/v1/targets/bulk-blocklist",
        json={"target_ids": [blocklistable_target.id], "confirm": True},
        headers={"X-API-Key": plain_key},
    )
    assert r.status_code == 403


def test_bulk_blocklist_archives_and_adds_pattern(api_key_client, blocklistable_target, db_session, test_tenant):
    from yads.models import DiscoveryDomainBlocklist
    from sqlmodel import select

    r = api_key_client.post(
        "/api/v1/targets/bulk-blocklist",
        json={"target_ids": [blocklistable_target.id], "confirm": True},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["blocklisted_count"] == 1
    assert body["archived_count"] == 1

    db_session.refresh(blocklistable_target)
    assert blocklistable_target.is_archived is True
    assert blocklistable_target.archived_reason == "blocklisted"

    pattern_row = db_session.exec(
        select(DiscoveryDomainBlocklist).where(
            DiscoveryDomainBlocklist.tenant_id == test_tenant.id,
            DiscoveryDomainBlocklist.pattern == "v1-blocklist-fixture.example.com",
        )
    ).first()
    assert pattern_row is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_v1_targets_blocklist.py -v`
Expected: FAIL with `404 Not Found` on every route.

- [ ] **Step 3: Add the endpoint**

Add this import to the top of `yads/api/routers/v1_targets.py`:

```python
from yads.models import DiscoveryDomainBlocklist
```

Append to `yads/api/routers/v1_targets.py`:

```python
class BulkBlocklistRequest(BaseModel):
    target_ids: List[int]
    confirm: bool


@router.post("/targets/bulk-blocklist", dependencies=[Depends(RequireScope("destructive"))])
async def bulk_blocklist_targets(
    payload: BulkBlocklistRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    if not payload.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to blocklist these targets")
    if not payload.target_ids:
        raise HTTPException(status_code=400, detail="No target_ids provided")

    owned_targets = session.exec(
        select(Target).where(
            Target.id.in_(set(payload.target_ids)),
            Target.tenant_id == api_key.tenant_id,
        )
    ).all()

    existing_patterns = set(session.exec(
        select(DiscoveryDomainBlocklist.pattern).where(
            DiscoveryDomainBlocklist.tenant_id == api_key.tenant_id,
        )
    ).all())

    blocked = 0
    archived = 0
    for target in owned_targets:
        pattern = target.domain.strip().lower()
        if pattern and pattern not in existing_patterns:
            session.add(DiscoveryDomainBlocklist(
                tenant_id=api_key.tenant_id,
                pattern=pattern,
                created_by=None,
                note="Added via /api/v1/targets/bulk-blocklist",
            ))
            existing_patterns.add(pattern)
            blocked += 1
        if not target.is_archived:
            target.is_archived = True
            target.archived_at = datetime.utcnow()
            target.archived_reason = "blocklisted"
            session.add(target)
            archived += 1

    session.commit()

    return {"blocklisted_count": blocked, "archived_count": archived}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_v1_targets_blocklist.py -v`
Expected: FAIL with `404 Not Found` until Task 8 registers the router. Proceed to commit.

- [ ] **Step 5: Commit**

```bash
git add yads/api/routers/v1_targets.py tests/test_v1_targets_blocklist.py
git commit -m "feat: add destructive-scoped bulk_blocklist_targets endpoint"
```

---

### Task 6: `v1_targets.py` — `get_target_changes`, `get_scan_status`, `get_network_context`

**Files:**
- Modify: `yads/api/routers/v1_targets.py`
- Test: `tests/test_v1_targets_status.py`

**Interfaces:**
- Consumes: `ChangeEvent` (`yads/models.py`); `get_scan_network_context` (`yads/core/redis_logger.py`).
- Produces: `GET /api/v1/targets/{target_id}/changes`, `GET /api/v1/targets/{target_id}/scan-status`, `GET /api/v1/targets/{target_id}/network-context` on the same router.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_v1_targets_status.py
"""Covers get_target_changes, get_scan_status, get_network_context."""

import pytest


@pytest.fixture
def status_target(db_session, test_tenant):
    from yads.models import Target
    from sqlmodel import select

    domain = "v1-status-fixture.example.com"
    existing = db_session.exec(select(Target).where(Target.domain == domain, Target.tenant_id == test_tenant.id)).first()
    if existing:
        return existing
    t = Target(domain=domain, tenant_id=test_tenant.id, tags=[], scan_status="idle")
    db_session.add(t)
    db_session.commit()
    db_session.refresh(t)
    return t


def test_get_target_changes_returns_list(api_key_client, status_target):
    r = api_key_client.get(f"/api/v1/targets/{status_target.id}/changes")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_get_target_changes_caps_limit(api_key_client, status_target):
    r = api_key_client.get(f"/api/v1/targets/{status_target.id}/changes", params={"limit": 500})
    assert r.status_code == 422  # FastAPI validation: le=100 on the query param


def test_get_target_changes_other_tenant_returns_404(api_key_client, db_session):
    from yads.models import Target, Tenant
    from sqlmodel import select

    other_tenant = Tenant(name="Other Tenant For Status Test")
    existing = db_session.exec(select(Tenant).where(Tenant.name == other_tenant.name)).first()
    if not existing:
        db_session.add(other_tenant)
        db_session.commit()
        db_session.refresh(other_tenant)
        existing = other_tenant

    other_target = db_session.exec(select(Target).where(Target.domain == "other-tenant-status.example.com")).first()
    if not other_target:
        other_target = Target(domain="other-tenant-status.example.com", tenant_id=existing.id, tags=[])
        db_session.add(other_target)
        db_session.commit()
        db_session.refresh(other_target)

    r = api_key_client.get(f"/api/v1/targets/{other_target.id}/changes")
    assert r.status_code == 404


def test_get_scan_status_returns_status(api_key_client, status_target):
    r = api_key_client.get(f"/api/v1/targets/{status_target.id}/scan-status")
    assert r.status_code == 200
    assert "status" in r.json()


def test_get_scan_status_other_tenant_returns_404(api_key_client, db_session):
    from yads.models import Target, Tenant
    from sqlmodel import select

    other_tenant = db_session.exec(select(Tenant).where(Tenant.name == "Other Tenant For Status Test")).first()
    if not other_tenant:
        other_tenant = Tenant(name="Other Tenant For Status Test")
        db_session.add(other_tenant)
        db_session.commit()
        db_session.refresh(other_tenant)

    other_target = db_session.exec(select(Target).where(Target.domain == "other-tenant-status.example.com")).first()
    if not other_target:
        other_target = Target(domain="other-tenant-status.example.com", tenant_id=other_tenant.id, tags=[])
        db_session.add(other_target)
        db_session.commit()
        db_session.refresh(other_target)

    r = api_key_client.get(f"/api/v1/targets/{other_target.id}/scan-status")
    assert r.status_code == 404


def test_get_network_context_returns_shape(api_key_client, status_target):
    r = api_key_client.get(f"/api/v1/targets/{status_target.id}/network-context")
    assert r.status_code == 200
    body = r.json()
    assert "network_context" in body
    assert "target_domain" in body
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_v1_targets_status.py -v`
Expected: FAIL with `404 Not Found` on every route.

- [ ] **Step 3: Add the endpoints**

Add these imports to the top of `yads/api/routers/v1_targets.py`:

```python
from yads.core.redis_logger import get_scan_network_context as get_network_ctx
from yads.models import ChangeEvent
```

Append to `yads/api/routers/v1_targets.py`:

```python
@router.get("/targets/{target_id}/changes", dependencies=[Depends(RequireScope("read"))])
async def get_target_changes(
    target_id: int,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
    limit: int = 30,
):
    if limit > 100:
        raise HTTPException(status_code=422, detail="limit must be <= 100")

    target = session.exec(
        select(Target).where(Target.id == target_id, Target.tenant_id == api_key.tenant_id)
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    rows = session.exec(
        select(ChangeEvent, ScanResult.module_name)
        .join(ScanResult, ChangeEvent.scan_result_id == ScanResult.id)
        .where(ScanResult.target_id == target_id)
        .order_by(ChangeEvent.created_at.desc())
        .limit(limit)
    ).all()

    return [
        {
            "id": ce.id,
            "module_name": mod_name,
            "event_type": ce.event_type,
            "description": ce.description,
            "detected_at": ce.created_at.isoformat(),
        }
        for ce, mod_name in rows
    ]


@router.get("/targets/{target_id}/scan-status", dependencies=[Depends(RequireScope("read"))])
async def get_scan_status(
    target_id: int,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    target = session.exec(
        select(Target).where(Target.id == target_id, Target.tenant_id == api_key.tenant_id)
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    status_msg = redis_client.get(f"scan:status:{target_id}")
    if status_msg:
        return {"status": status_msg}
    return {"status": target.scan_progress or target.scan_status}


@router.get("/targets/{target_id}/network-context", dependencies=[Depends(RequireScope("read"))])
async def get_network_context(
    target_id: int,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    target = session.exec(
        select(Target).where(Target.id == target_id, Target.tenant_id == api_key.tenant_id)
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    context = get_network_ctx(target_id)
    return {"network_context": context, "target_domain": target.domain}
```

Note: `get_scan_status`'s Redis value comes back as `bytes` or `str` depending on the `redis_client` decode setting already configured elsewhere in this codebase (see `yads/database.py`'s `redis_client` construction) — this mirrors the exact existing behavior of `targets.py`'s `get_scan_status` (`r.get(...)` returned directly), so no new decoding logic is introduced here; if the existing endpoint works today, this one will too.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_v1_targets_status.py -v`
Expected: FAIL with `404 Not Found` until Task 8 registers the router (note which tests are coincidentally passing right now due to the same "assert 404" pattern established in Wave 1's Task 3/4/5 — report it, don't chase it). Proceed to commit.

- [ ] **Step 5: Commit**

```bash
git add yads/api/routers/v1_targets.py tests/test_v1_targets_status.py
git commit -m "feat: add get_target_changes, get_scan_status, get_network_context endpoints"
```

---

### Task 7: Register `v1_targets.router` in `main.py`

**Files:**
- Modify: `yads/api/main.py`
- Test: none new — this task makes Tasks 1-6's existing tests pass for real

**Interfaces:**
- Consumes: `v1_targets.router` (Tasks 1-6).

- [ ] **Step 1: Confirm the pre-registration failures**

Run: `pytest tests/test_v1_targets_read.py tests/test_v1_targets_add.py tests/test_v1_targets_delete.py tests/test_v1_targets_archive.py tests/test_v1_targets_blocklist.py tests/test_v1_targets_status.py -v`
Expected: Every non-401/403 assertion fails with `404 Not Found` — confirms the router genuinely isn't registered yet.

- [ ] **Step 2: Register the router**

In `yads/api/main.py`, extend the existing router import line to add `v1_targets` (alongside `v1, v1_queue, v1_tags, v1_scan` from Wave 1), and add `app.include_router(v1_targets.router)` immediately after `app.include_router(v1_scan.router)`.

- [ ] **Step 3: Run the full new-route test suite to verify it passes**

Run: `pytest tests/test_v1_targets_read.py tests/test_v1_targets_add.py tests/test_v1_targets_delete.py tests/test_v1_targets_archive.py tests/test_v1_targets_blocklist.py tests/test_v1_targets_status.py -v`
Expected: All PASS.

- [ ] **Step 4: Run the full existing test suite to check for regressions**

Run: `pytest tests/ -q --ignore=tests/test_cleanup_logging.py --ignore=tests/test_changelog.py --ignore=tests/test_version.py`
Expected: same 12 pre-existing, unrelated failures as always (auth redirects, MFA enforcement, targets-page smoke, SSRF), plus all new tests from this plan passing, zero new failures. Reconcile the exact new-passing-test count against the test files you added in Tasks 1-6 (do the arithmetic, don't just eyeball "no new failures").

- [ ] **Step 5: Commit**

```bash
git add yads/api/main.py
git commit -m "feat: register v1_targets router"
```

---

### Task 8: `yads-mcp` — Target & Asset Management tools, part 1 (read + add)

**Files:**
- Modify: `yads-mcp/yads_mcp/server.py`
- Test: `yads-mcp/tests/test_targets_tools.py`

**Interfaces:**
- Consumes: `client()`, `_ok()` (`yads_mcp/client.py`, `yads_mcp/server.py`); the yads endpoints from Tasks 1-2.
- Produces: a fourth tool group, `# --- Target & Asset Management ---`, with `list_targets`, `get_target`, `add_target`.

- [ ] **Step 1: Write the failing test**

```python
# yads-mcp/tests/test_targets_tools.py
"""Covers the Target & Asset Management tool group."""

import pytest


def test_list_targets_tool_returns_shape():
    from yads_mcp.server import list_targets
    result = list_targets()
    assert "targets" in result
    assert "total" in result


def test_add_and_get_target_tool():
    from yads_mcp.server import add_target, get_target
    added = add_target(domain="yads-mcp-wave2-fixture.example.com")
    assert added["domain"] == "yads-mcp-wave2-fixture.example.com"

    fetched = get_target(target_id=added["id"])
    assert fetched["domain"] == "yads-mcp-wave2-fixture.example.com"


def test_list_targets_tool_filters_by_domain_search():
    from yads_mcp.server import add_target, list_targets
    add_target(domain="yads-mcp-wave2-search-fixture.example.com")
    result = list_targets(domain_search="wave2-search-fixture")
    domains = [t["domain"] for t in result["targets"]]
    assert "yads-mcp-wave2-search-fixture.example.com" in domains
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/mrmarco/Documents/gitlab/yads-project/yads-mcp && .venv/bin/pytest tests/test_targets_tools.py -v` (with the standard `YADS_MCP_TEST_REPO_ROOT` + test-container env vars from Wave 1's Task 10 established pattern)
Expected: FAIL with `ImportError: cannot import name 'list_targets' from 'yads_mcp.server'`

- [ ] **Step 3: Add the tool group**

Append to `yads_mcp/server.py` (after the Scanning Execution group, before `def main():`):

```python
# --- Target & Asset Management ---


@mcp.tool()
def list_targets(
    tag: str | None = None,
    online: bool | None = None,
    scan_status: str | None = None,
    domain_search: str | None = None,
    archived: bool = False,
    last_scanned_before: str | None = None,
    page: int = 1,
    limit: int = 20,
) -> dict:
    """List targets for this key's tenant, with optional filters (combined
    with AND). limit is capped at 100 server-side. scan_status accepts
    "idle"/"queued"/"running"/"failed". last_scanned_before is an ISO date
    string; matches targets scanned before that date OR never scanned."""
    params: dict = {"archived": archived, "page": page, "limit": limit}
    if tag:
        params["tag"] = tag
    if online is not None:
        params["online"] = online
    if scan_status:
        params["scan_status"] = scan_status
    if domain_search:
        params["domain_search"] = domain_search
    if last_scanned_before:
        params["last_scanned_before"] = last_scanned_before
    with client() as c:
        return _ok(c.get("/api/v1/targets", params=params))


@mcp.tool()
def get_target(target_id: int) -> dict:
    """Lean summary of one target: domain, scan status/progress, tags,
    archive state, when it was created, when it was last scanned, and how
    many distinct scanner modules have results for it. For the full
    per-module scan data, use scan_get_findings() (Wave 1) or
    get_target_changes() for its recent change history."""
    with client() as c:
        return _ok(c.get(f"/api/v1/targets/{target_id}"))


@mcp.tool()
def add_target(domain: str) -> dict:
    """Add a target by domain, or return the existing one if it's already
    present (find-or-create). Blocked for internal/private-network domains
    by SSRF protection. Does not trigger a scan -- follow up with
    scan_trigger_by_target_id() if you want one."""
    with client() as c:
        return _ok(c.post("/api/v1/targets", json={"domain": domain}))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/mrmarco/Documents/gitlab/yads-project/yads-mcp && .venv/bin/pytest tests/test_targets_tools.py -v`
Expected: PASS (3 passed). Note: these tests will be genuinely slow-but-not-hanging if run alongside the rest of the suite due to real Celery-inspect timeouts elsewhere in the session (established Wave 1 finding) — not a regression if this file alone passes quickly.

- [ ] **Step 5: Commit**

```bash
cd /home/mrmarco/Documents/gitlab/yads-project/yads-mcp
git add yads_mcp/server.py tests/test_targets_tools.py
git commit -m "feat: add list_targets, get_target, add_target MCP tools"
```

---

### Task 9: `yads-mcp` — Target & Asset Management tools, part 2 (delete/archive/blocklist)

**Files:**
- Modify: `yads-mcp/yads_mcp/server.py`
- Test: `yads-mcp/tests/test_targets_tools.py` (append to the file from Task 8)

**Interfaces:**
- Consumes: `client()`, `_ok()`; the yads endpoints from Tasks 3-5.
- Produces: `bulk_delete_targets`, `undo_bulk_delete_targets`, `bulk_archive_targets`, `archive_dead_targets`, `restore_target`, `bulk_blocklist_targets` appended to the same tool group.

- [ ] **Step 1: Write the failing tests**

Append to `yads-mcp/tests/test_targets_tools.py`:

```python
def test_bulk_delete_and_undo_tools():
    from yads_mcp.server import add_target, bulk_delete_targets, undo_bulk_delete_targets

    added = add_target(domain="yads-mcp-wave2-delete-fixture.example.com")
    result = bulk_delete_targets(target_ids=[added["id"]], confirm=True)
    assert result["deleted_count"] == 1
    assert result["undo_batch"]

    undo_result = undo_bulk_delete_targets(undo_batch=result["undo_batch"])
    assert undo_result["restored_count"] == 1


def test_bulk_delete_requires_confirm_tool():
    from yads_mcp.server import add_target, bulk_delete_targets
    import pytest

    added = add_target(domain="yads-mcp-wave2-delete-noconfirm.example.com")
    with pytest.raises(RuntimeError, match="400"):
        bulk_delete_targets(target_ids=[added["id"]], confirm=False)


def test_bulk_archive_and_restore_tools():
    from yads_mcp.server import add_target, bulk_archive_targets, restore_target

    added = add_target(domain="yads-mcp-wave2-archive-fixture.example.com")
    result = bulk_archive_targets(target_ids=[added["id"]])
    assert result["archived_count"] == 1

    restored = restore_target(target_id=added["id"])
    assert restored["is_archived"] is False


def test_archive_dead_targets_tool():
    from yads_mcp.server import archive_dead_targets
    result = archive_dead_targets()
    assert "archived_count" in result


def test_bulk_blocklist_tool():
    from yads_mcp.server import add_target, bulk_blocklist_targets

    added = add_target(domain="yads-mcp-wave2-blocklist-fixture.example.com")
    result = bulk_blocklist_targets(target_ids=[added["id"]], confirm=True)
    assert result["blocklisted_count"] == 1
    assert result["archived_count"] == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/mrmarco/Documents/gitlab/yads-project/yads-mcp && .venv/bin/pytest tests/test_targets_tools.py -v -k "bulk_delete or bulk_archive or archive_dead or bulk_blocklist"`
Expected: FAIL with `ImportError: cannot import name 'bulk_delete_targets' from 'yads_mcp.server'`

- [ ] **Step 3: Add the tools**

Append to `yads_mcp/server.py`'s `# --- Target & Asset Management ---` group (after `add_target`, before `def main():`):

```python
@mcp.tool()
def bulk_delete_targets(target_ids: list[int], confirm: bool) -> dict:
    """Permanently delete targets and all their scan history/findings --
    irreversible beyond a 60-second undo window (see
    undo_bulk_delete_targets; the domain/tags are restorable, scan history
    is not). Requires the 'destructive' scope on this API key."""
    with client() as c:
        return _ok(c.post("/api/v1/targets/bulk-delete", json={"target_ids": target_ids, "confirm": confirm}))


@mcp.tool()
def undo_bulk_delete_targets(undo_batch: str) -> dict:
    """Re-create targets deleted by a prior bulk_delete_targets call, using
    the undo_batch id from that call's response. Only works within 60
    seconds of the delete -- restores domain/tags only, not scan history."""
    with client() as c:
        return _ok(c.post("/api/v1/targets/bulk-delete/undo", json={"undo_batch": undo_batch}))


@mcp.tool()
def bulk_archive_targets(target_ids: list[int]) -> dict:
    """Archive targets -- stops them from being scanned, but fully
    reversible via restore_target(). Not destructive."""
    with client() as c:
        return _ok(c.post("/api/v1/targets/bulk-archive", json={"target_ids": target_ids}))


@mcp.tool()
def archive_dead_targets() -> dict:
    """Archive every target in this key's tenant whose most recent DNS
    scan returned empty records (i.e. the domain no longer resolves).
    Tenant-wide sweep, no target_ids needed. Reversible via
    restore_target()."""
    with client() as c:
        return _ok(c.post("/api/v1/targets/archive-dead"))


@mcp.tool()
def restore_target(target_id: int) -> dict:
    """Un-archive a target, clearing its archived state so it's scanned
    again."""
    with client() as c:
        return _ok(c.post(f"/api/v1/targets/{target_id}/restore"))


@mcp.tool()
def bulk_blocklist_targets(target_ids: list[int], confirm: bool) -> dict:
    """Add each target's domain to this tenant's Discovery blocklist
    (exact match -- future Discovery runs won't re-add it) AND archive the
    target. Requires the 'destructive' scope: unlike plain archiving,
    reversing this needs both restore_target() and manually removing the
    blocklist entry (no blocklist-management tool exists yet), so there's
    no clean single-action undo."""
    with client() as c:
        return _ok(c.post("/api/v1/targets/bulk-blocklist", json={"target_ids": target_ids, "confirm": confirm}))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/mrmarco/Documents/gitlab/yads-project/yads-mcp && .venv/bin/pytest tests/test_targets_tools.py -v`
Expected: PASS (8 passed — 3 from Task 8 + 5 from this task).

- [ ] **Step 5: Commit**

```bash
cd /home/mrmarco/Documents/gitlab/yads-project/yads-mcp
git add yads_mcp/server.py tests/test_targets_tools.py
git commit -m "feat: add bulk_delete/undo/archive/blocklist MCP tools"
```

---

### Task 10: `yads-mcp` — Target & Asset Management tools, part 3 (status/history) + README

**Files:**
- Modify: `yads-mcp/yads_mcp/server.py`
- Modify: `yads-mcp/README.md`
- Test: `yads-mcp/tests/test_targets_tools.py` (append)

**Interfaces:**
- Consumes: `client()`, `_ok()`; the yads endpoints from Task 6.
- Produces: `get_target_changes`, `get_scan_status`, `get_network_context` — completing the 12-tool Wave 2 surface.

- [ ] **Step 1: Write the failing tests**

Append to `yads-mcp/tests/test_targets_tools.py`:

```python
def test_get_target_changes_tool():
    from yads_mcp.server import add_target, get_target_changes

    added = add_target(domain="yads-mcp-wave2-changes-fixture.example.com")
    result = get_target_changes(target_id=added["id"])
    assert isinstance(result, list)


def test_get_scan_status_tool():
    from yads_mcp.server import add_target, get_scan_status

    added = add_target(domain="yads-mcp-wave2-status-fixture.example.com")
    result = get_scan_status(target_id=added["id"])
    assert "status" in result


def test_get_network_context_tool():
    from yads_mcp.server import add_target, get_network_context

    added = add_target(domain="yads-mcp-wave2-netctx-fixture.example.com")
    result = get_network_context(target_id=added["id"])
    assert "network_context" in result
    assert result["target_domain"] == "yads-mcp-wave2-netctx-fixture.example.com"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/mrmarco/Documents/gitlab/yads-project/yads-mcp && .venv/bin/pytest tests/test_targets_tools.py -v -k "changes or scan_status or network_context"`
Expected: FAIL with `ImportError: cannot import name 'get_target_changes' from 'yads_mcp.server'`

- [ ] **Step 3: Add the tools**

Append to `yads_mcp/server.py`'s `# --- Target & Asset Management ---` group (after `bulk_blocklist_targets`, before `def main():`):

```python
@mcp.tool()
def get_target_changes(target_id: int, limit: int = 30) -> list[dict]:
    """Recent detected changes for a target (new/changed/removed findings
    across scans), newest first. limit capped at 100 server-side."""
    with client() as c:
        return _ok(c.get(f"/api/v1/targets/{target_id}/changes", params={"limit": limit}))


@mcp.tool()
def get_scan_status(target_id: int) -> dict:
    """Current scan status/progress message for a target -- live if a scan
    is running, otherwise the last known state ("idle", "queued", etc.)."""
    with client() as c:
        return _ok(c.get(f"/api/v1/targets/{target_id}/scan-status"))


@mcp.tool()
def get_network_context(target_id: int) -> dict:
    """Network context captured during a target's scans -- the external IP
    YADS scanned from and the IPs the target resolved to at scan time."""
    with client() as c:
        return _ok(c.get(f"/api/v1/targets/{target_id}/network-context"))
```

Update `yads-mcp/README.md`'s "## Tools (Wave 1)" heading to "## Tools" and add a new section after the Scanning Execution list:

```markdown
**Target & Asset Management** (Wave 2)
- `list_targets(tag=None, online=None, scan_status=None, domain_search=None, archived=False, last_scanned_before=None, page=1, limit=20)`
- `get_target(target_id)`
- `add_target(domain)`
- `bulk_delete_targets(target_ids, confirm)` — destructive, 60s undo window
- `undo_bulk_delete_targets(undo_batch)`
- `bulk_archive_targets(target_ids)` / `archive_dead_targets()` / `restore_target(target_id)`
- `bulk_blocklist_targets(target_ids, confirm)` — destructive, no undo
- `get_target_changes(target_id, limit=30)`
- `get_scan_status(target_id)`
- `get_network_context(target_id)`
```

Also update the line right below the tools heading that currently says "Waves 2–10 (Target/Asset Management, Reports & Export, ...) are tracked separately" — remove "Target/Asset Management" from that list since it's now shipped, leaving "Waves 3–10 (Reports & Export, Findings & Compliance, OSINT/Discovery/Intelligence, Integrations/Webhooks/Notifications) are tracked separately, each with its own design spec." (Tenant/User Admin and System/Infra Admin are permanently excluded from the roadmap per an explicit user decision after Wave 1 shipped — do not list them here at all, not even as "out of scope.")

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/mrmarco/Documents/gitlab/yads-project/yads-mcp && .venv/bin/pytest tests/ -v`
Expected: All PASS (Task 8's 3 + Task 9's 5 + this task's 3 = 11 new tests, plus Wave 1's existing tests, all passing — reconcile the exact total against what's in each test file, don't just eyeball "no failures").

- [ ] **Step 5: Commit**

```bash
cd /home/mrmarco/Documents/gitlab/yads-project/yads-mcp
git add yads_mcp/server.py tests/test_targets_tools.py README.md
git commit -m "feat: add get_target_changes/get_scan_status/get_network_context MCP tools, complete Wave 2"
```

---

## Self-Review Notes

- **Spec coverage:** §1 (scope trim) → reflected in the 12-tool list across Tasks 1-10, no "send to discovery"/file-import/logo-upload tools present. §2 (router shape) → Task 1. §3 (tool-by-tool design) → each subsection maps to its named task (list_targets/get_target → Task 1, add_target → Task 2, bulk_delete+undo → Task 3, archive family → Task 4, blocklist → Task 5, status/history → Task 6). §4 (scope table) → every route's `dependencies=[Depends(RequireScope(...))]` matches the table exactly; verify during review that no route was left with only `require_tenant_scoped_key` and no `RequireScope`. §5 (MCP group) → Tasks 8-10. §6 (out of scope) → nothing in this plan builds Discovery-session creation, blocklist CRUD beyond the inline bulk-blocklist insert, file import, or logo upload.
- **Placeholder scan:** no TBD/TODO found; every step has real code.
- **Type consistency:** `target_ids: List[int]` (yads-side Pydantic models, Tasks 3-5) matches `target_ids: list[int]` (yads-mcp tool signatures, Tasks 9). `confirm: bool` has no default anywhere it appears (yads-side `BulkDeleteRequest`/`BulkBlocklistRequest`, yads-mcp tool signatures) — consistent with Wave 1's established convention. `undo_batch: str` matches between `UndoDeleteRequest`/`undo_bulk_delete_targets` tool. The `_ApiKeyAsUser` shim in Task 3 is a local class (not imported from `v1_scan.py`'s module-level one) since it's only needed for one call site in this file — acceptable minor duplication rather than a cross-file import of a private helper from an unrelated router module.
