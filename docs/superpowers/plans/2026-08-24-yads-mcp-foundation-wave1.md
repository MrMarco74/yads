# YADS MCP Foundation + Wave 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a new API-key-authenticated `/api/v1` surface to YADS covering Queue & Scan Control, Tagging & Organization, and Scanning Execution (19 operations), plus a new sibling repo `yads-mcp` exposing them as MCP tools for LLM agents.

**Architecture:** Three new FastAPI routers (`v1_queue.py`, `v1_tags.py`, `v1_scan.py`) mounted at `/api/v1`, authenticated via the existing `get_api_key`/`RequireScope` dependencies, reusing existing business-logic helpers from `queue.py`/`tags.py`/`targets.py` by import rather than duplicating them. A new `destructive` API-key scope gates irreversible operations, backed by a required `confirm: bool` field checked server-side. `yads-mcp` is a separate thin `httpx`-based MCP server repo (mirroring `labcontrol_mcp`'s shape exactly) with zero direct DB/Celery access — every tool is one HTTP call to the new endpoints.

**Tech Stack:** FastAPI, SQLModel, Celery, `mcp` Python SDK (`MCPServer`), `httpx`, pytest + Starlette `TestClient`.

**Spec:** `docs/superpowers/specs/2026-08-24-yads-mcp-foundation-design.md`

## Global Constraints

- New scope name is exactly `"destructive"` — added to `VALID_SCOPES` in `yads/api/routers/api_keys.py:15`.
- Destructive endpoints require BOTH `RequireScope("destructive")` AND a request-body `confirm: bool` that must be `true` (400 otherwise) — the scope is not sufficient on its own.
- New endpoints tenant-scope every query via `api_key.tenant_id` (never a client-supplied tenant parameter), following `v1.py`'s existing pattern.
- New endpoints reuse existing helper functions from `queue.py`/`tags.py`/`targets.py` by import wherever those helpers already exist and are tenant-parameterizable — do not duplicate their logic.
- Two deliberate behavior tightenings versus the existing HTML routes (per spec §6): `tags_list`/`tags_add_to_target`/`tags_remove_from_target`'s new API-key versions gain tenant scoping that the HTML originals lack; `scan_trigger` (existing `v1.py` route) gains a `RequireScope("scan_execute")` dependency it didn't have before.
- `yads-mcp` has no direct database, Redis, or Celery access — every tool body is exactly one `httpx` call via `yads_mcp.client.client()`.
- `yads-mcp/yads_mcp/server.py` follows `labcontrol_mcp/server.py`'s exact shape: `mcp = MCPServer("yads")`, `@mcp.tool()` per operation, tools grouped under `# --- <Group Name> ---` comment headers matching this plan's task groups.
- Destructive `yads-mcp` tools declare `confirm: bool` as a required parameter (no default) — unlike `labcontrol_mcp`'s `confirm: bool = True` convenience default, per spec §8.

---

### Task 1: Add the `destructive` API-key scope

**Files:**
- Modify: `yads/api/routers/api_keys.py:15`
- Test: `tests/test_api_keys_destructive_scope.py`

**Interfaces:**
- Produces: `VALID_SCOPES` now includes `"destructive"`, importable as `from yads.api.routers.api_keys import VALID_SCOPES`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_api_keys_destructive_scope.py
"""Confirms the new 'destructive' scope is accepted by API-key creation."""


def test_destructive_is_a_valid_scope():
    from yads.api.routers.api_keys import VALID_SCOPES
    assert "destructive" in VALID_SCOPES


def test_create_key_with_destructive_scope_succeeds(admin_client):
    r = admin_client.post(
        "/api-keys/",
        params={"name": "pytest-destructive-key", "scopes": ["read", "destructive"]},
    )
    assert r.status_code == 201
    body = r.json()
    assert "destructive" in body["scopes"] or "token" in body
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_api_keys_destructive_scope.py -v`
Expected: FAIL on `assert "destructive" in VALID_SCOPES` (AssertionError) — the scope doesn't exist yet. (The second test may also 400 with "Invalid scopes: ['destructive']".)

- [ ] **Step 3: Add the scope**

In `yads/api/routers/api_keys.py:15`, change:
```python
VALID_SCOPES = {"read", "write", "scan_execute", "provision_tenant"}
```
to:
```python
VALID_SCOPES = {"read", "write", "scan_execute", "provision_tenant", "destructive"}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_api_keys_destructive_scope.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add yads/api/routers/api_keys.py tests/test_api_keys_destructive_scope.py
git commit -m "feat: add destructive API-key scope for yads-mcp foundation"
```

---

### Task 2: `api_key` test fixture

The existing `tests/conftest.py` has no fixture that authenticates via `X-API-Key` (only cookie/JWT `admin_client`). Every remaining task in this plan tests API-key-authenticated endpoints, so this fixture is needed before Task 3.

**Files:**
- Modify: `tests/conftest.py`
- Test: `tests/test_api_key_fixture.py`

**Interfaces:**
- Produces: `api_key_headers` fixture — a `dict` of `{"X-API-Key": "<plain-key>"}` for a key with scopes `["read", "write", "scan_execute", "destructive"]`, scoped to `test_tenant`. `api_key_client` fixture — a `TestClient` with those headers pre-set.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_api_key_fixture.py
"""Confirms the new api_key fixtures authenticate against a real API-key row."""


def test_api_key_headers_authenticate(api_key_client):
    r = api_key_client.get("/api/v1/findings")
    assert r.status_code in (200, 404)  # 404 = no findings yet, not an auth failure


def test_api_key_headers_missing_key_is_rejected(client):
    r = client.get("/api/v1/findings")
    assert r.status_code == 401
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_api_key_fixture.py -v`
Expected: FAIL with `fixture 'api_key_client' not found`

- [ ] **Step 3: Add the fixtures**

Append to `tests/conftest.py` (after the existing `test_tenant` fixture):

```python
# ── API key fixtures (X-API-Key header auth, distinct from cookie auth) ──────

@pytest.fixture(scope="session")
def api_key_headers(db_session, test_tenant):
    """A real APIKey row (scopes: read, write, scan_execute, destructive),
    scoped to test_tenant. Returns headers dict ready to attach to a client."""
    from yads.models import APIKey
    from yads.auth.security import generate_api_key
    from sqlmodel import select

    existing = db_session.exec(
        select(APIKey).where(APIKey.name == "pytest-fixture-key", APIKey.tenant_id == test_tenant.id)
    ).first()
    if existing:
        # Key was already created in a prior test run against a reused
        # container; the plain key itself isn't recoverable from the hash,
        # so recreate a fresh key row instead of reusing this stale one.
        db_session.delete(existing)
        db_session.commit()

    plain_key, prefix, key_hash = generate_api_key()
    key_row = APIKey(
        tenant_id=test_tenant.id,
        name="pytest-fixture-key",
        key_prefix=prefix,
        key_hash=key_hash,
        scopes=["read", "write", "scan_execute", "destructive"],
    )
    db_session.add(key_row)
    db_session.commit()

    yield {"X-API-Key": plain_key}


@pytest.fixture(scope="session")
def api_key_client(client, api_key_headers):
    """TestClient pre-loaded with a scoped API key (see api_key_headers)."""
    client.headers.update(api_key_headers)
    return client
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_api_key_fixture.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add tests/conftest.py tests/test_api_key_fixture.py
git commit -m "test: add api_key_client fixture for API-key-authenticated route tests"
```

---

### Task 3: `v1_queue.py` — status, pause, resume, cancel

**Files:**
- Create: `yads/api/routers/v1_queue.py`
- Test: `tests/test_v1_queue_control.py`

**Interfaces:**
- Consumes: `get_api_key`, `RequireScope` (`yads/auth/deps.py`); `get_session` (`yads/database.py`); `filter_tasks_by_tenant`, `extract_tenant_from_task`, `mark_task_cancelled`, `prettify_task_name` (`yads/api/routers/queue.py`, module-level functions, importable as-is); `get_rate_limited_module_count() -> int` (`yads/core/module_status.py`, no args, global count — not tenant-scoped); `celery_app` (`yads/worker.py`).
- Produces: `router = APIRouter(prefix="/api/v1", tags=["API v1 — Queue"])` with routes `GET /api/v1/queue/status`, `POST /api/v1/queue/control`, `POST /api/v1/queue/tasks/{task_id}/cancel`. Task 4 adds `purge`/`undo-purge` to this same router.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_v1_queue_control.py
"""Covers GET /api/v1/queue/status, POST /api/v1/queue/control,
POST /api/v1/queue/tasks/{id}/cancel."""


def test_queue_status_requires_api_key(client):
    r = client.get("/api/v1/queue/status")
    assert r.status_code == 401


def test_queue_status_returns_expected_shape(api_key_client):
    r = api_key_client.get("/api/v1/queue/status")
    assert r.status_code == 200
    body = r.json()
    for key in ("queue_active", "queued_count", "running_count", "active_tasks", "reserved_tasks", "rate_limited_module_count"):
        assert key in body


def test_queue_control_pause_and_resume(api_key_client):
    r = api_key_client.post("/api/v1/queue/control", json={"action": "pause"})
    assert r.status_code == 200
    assert r.json()["queue_active"] is False

    r = api_key_client.post("/api/v1/queue/control", json={"action": "resume"})
    assert r.status_code == 200
    assert r.json()["queue_active"] is True


def test_queue_control_rejects_bad_action(api_key_client):
    r = api_key_client.post("/api/v1/queue/control", json={"action": "not-a-real-action"})
    assert r.status_code == 400


def test_cancel_task_not_found_returns_404(api_key_client):
    r = api_key_client.post("/api/v1/queue/tasks/nonexistent-task-id/cancel")
    assert r.status_code == 404
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_v1_queue_control.py -v`
Expected: FAIL — `404 Not Found` on every request (route doesn't exist yet).

- [ ] **Step 3: Create the router**

```python
# yads/api/routers/v1_queue.py
"""API-key-authenticated queue control surface for yads-mcp and other
machine clients. Mirrors the tenant-scoped subset of the cookie-session
queue.py routes -- see docs/superpowers/specs/2026-08-24-yads-mcp-foundation-design.md
section 5.1.
"""

from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, func as sqlfunc, select

from yads.api.routers.queue import (
    extract_tenant_from_task,
    filter_tasks_by_tenant,
    mark_task_cancelled,
    prettify_task_name,
)
from yads.auth.deps import get_api_key
from yads.core.module_status import get_rate_limited_module_count
from yads.database import get_session
from yads.models import APIKey, SystemConfig, Target
from yads.worker import celery_app

router = APIRouter(prefix="/api/v1", tags=["API v1 — Queue"])


@router.get("/queue/status")
async def queue_status(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(get_api_key)],
):
    conf = session.get(SystemConfig, "QUEUE_ACTIVE")
    queue_active = not (conf and conf.value.lower() == "false")

    queued_count = session.exec(
        select(sqlfunc.count()).select_from(Target).where(
            Target.tenant_id == api_key.tenant_id,
            Target.scan_status == "queued",
            Target.is_archived == False,
        )
    ).one()
    running_count = session.exec(
        select(sqlfunc.count()).select_from(Target).where(
            Target.tenant_id == api_key.tenant_id,
            Target.scan_status == "running",
            Target.is_archived == False,
        )
    ).one()

    active_tasks = []
    reserved_tasks = []
    try:
        i = celery_app.control.inspect(timeout=5.0)
        for worker, tasks in (i.active() or {}).items():
            for task in filter_tasks_by_tenant(tasks, api_key.tenant_id):
                active_tasks.append({"id": task.get("id"), "name": prettify_task_name(task.get("name", "")), "args": task.get("args", [])})
        for worker, tasks in (i.reserved() or {}).items():
            for task in filter_tasks_by_tenant(tasks, api_key.tenant_id):
                reserved_tasks.append({"id": task.get("id"), "name": prettify_task_name(task.get("name", "")), "args": task.get("args", [])})
    except Exception:
        pass

    return {
        "queue_active": queue_active,
        "queued_count": queued_count,
        "running_count": running_count,
        "active_tasks": active_tasks,
        "reserved_tasks": reserved_tasks,
        "rate_limited_module_count": get_rate_limited_module_count(),
    }


class QueueControlRequest(BaseModel):
    action: str


@router.post("/queue/control")
async def queue_control(
    payload: QueueControlRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(get_api_key)],
):
    if payload.action not in ("pause", "resume"):
        raise HTTPException(status_code=400, detail="action must be 'pause' or 'resume'")

    conf = session.get(SystemConfig, "QUEUE_ACTIVE")
    if not conf:
        conf = SystemConfig(key="QUEUE_ACTIVE", value="true")

    # Note: this action is fleet-wide, not tenant-scoped, matching the
    # existing cookie-session control_queue behavior exactly -- see
    # spec section 6, item 1. A key with only "write" (not "destructive")
    # can pause every tenant's scans; this is an inherited inconsistency,
    # not a new one introduced here.
    if payload.action == "pause":
        conf.value = "false"
        session.add(conf)
        session.commit()
        celery_app.control.cancel_consumer("celery", reply=False)
        celery_app.control.cancel_consumer("discovery", reply=False)
    else:
        conf.value = "true"
        session.add(conf)
        session.commit()
        celery_app.control.add_consumer("celery", reply=False)
        celery_app.control.add_consumer("discovery", reply=False)

    return {"queue_active": payload.action == "resume"}


@router.post("/queue/tasks/{task_id}/cancel")
async def cancel_task(
    task_id: str,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(get_api_key)],
):
    i = celery_app.control.inspect(timeout=5.0)
    task_tenant_id: Optional[int] = None
    target_id: Optional[int] = None
    task_state: Optional[str] = None

    if i:
        for state_name, getter in (("reserved", i.reserved), ("active", i.active)):
            for worker, tasks in (getter() or {}).items():
                for task in tasks:
                    if task.get("id") == task_id:
                        task_state = state_name
                        task_tenant_id = extract_tenant_from_task(task)
                        args = task.get("args", [])
                        target_id = args[0] if args else None
                        break
                if task_state:
                    break
            if task_state:
                break

    if task_state is None:
        raise HTTPException(status_code=404, detail="Task not found in queue")

    if task_tenant_id != api_key.tenant_id:
        raise HTTPException(status_code=403, detail="Not authorized to cancel this task")

    mark_task_cancelled(task_id)
    celery_app.control.revoke(task_id, terminate=True)

    if target_id:
        target = session.get(Target, target_id)
        if target and target.scan_status in ("queued", "running"):
            target.scan_status = "idle"
            target.scan_progress = "Cancelled via API"
            session.add(target)
            session.commit()

    return {"status": "cancelled", "task_id": task_id, "task_state": task_state, "target_id": target_id}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_v1_queue_control.py -v`
Expected: All routes 404 until Task 8 registers the router in `main.py`. If your test runner requires the router registered to run this file in isolation, register it now via Task 8's Step 3 before running this test, then complete Task 8's remaining steps at the end as planned. Otherwise: FAIL is expected at this point with `404 Not Found` for `/api/v1/queue/status` etc. — this is correct per the file-then-register split in this plan; do not treat it as a blocker, proceed to Step 5.

- [ ] **Step 5: Commit**

```bash
git add yads/api/routers/v1_queue.py tests/test_v1_queue_control.py
git commit -m "feat: add API-key-authenticated queue status/control/cancel endpoints"
```

---

### Task 4: `v1_queue.py` — purge + undo-purge (destructive)

**Files:**
- Modify: `yads/api/routers/v1_queue.py`
- Test: `tests/test_v1_queue_purge.py`

**Interfaces:**
- Consumes: `RequireScope` (`yads/auth/deps.py`); everything Task 3 already imports into `v1_queue.py`.
- Produces: `POST /api/v1/queue/purge`, `POST /api/v1/queue/undo-purge` on the same router.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_v1_queue_purge.py
"""Covers POST /api/v1/queue/purge and POST /api/v1/queue/undo-purge —
the destructive-scope + confirm:bool pair."""


def test_purge_requires_confirm_true(api_key_client):
    r = api_key_client.post("/api/v1/queue/purge", json={"confirm": False})
    assert r.status_code == 400


def test_purge_with_confirm_succeeds(api_key_client):
    r = api_key_client.post("/api/v1/queue/purge", json={"confirm": True})
    assert r.status_code == 200
    body = r.json()
    assert "purged_count" in body
    assert "revoked_count" in body


def test_purge_rejects_key_without_destructive_scope(db_session, test_tenant, client):
    from yads.models import APIKey
    from yads.auth.security import generate_api_key

    plain_key, prefix, key_hash = generate_api_key()
    key_row = APIKey(
        tenant_id=test_tenant.id, name="pytest-no-destructive",
        key_prefix=prefix, key_hash=key_hash, scopes=["read", "write"],
    )
    db_session.add(key_row)
    db_session.commit()

    r = client.post("/api/v1/queue/purge", json={"confirm": True}, headers={"X-API-Key": plain_key})
    assert r.status_code == 403


def test_undo_purge_with_expired_batch_returns_404(api_key_client):
    r = api_key_client.post("/api/v1/queue/undo-purge", json={"undo_batch": "nonexistent-batch-id"})
    assert r.status_code == 404
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_v1_queue_purge.py -v`
Expected: FAIL with `404 Not Found` (routes don't exist yet).

- [ ] **Step 3: Add purge and undo-purge to the router**

Add these imports to the top of `yads/api/routers/v1_queue.py` (alongside the existing ones from Task 3):

```python
import base64
import json
import uuid as _uuid

from sqlmodel import and_, or_

from yads.auth.deps import RequireScope
from yads.database import redis_client
```

Append to `yads/api/routers/v1_queue.py`:

```python
class ConfirmRequest(BaseModel):
    confirm: bool


@router.post("/queue/purge", dependencies=[Depends(RequireScope("destructive"))])
async def purge_queue(
    payload: ConfirmRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(get_api_key)],
):
    if not payload.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to purge the queue")

    purged_count = 0
    undo_tasks = []
    queue_len = redis_client.llen("celery")
    if queue_len > 0:
        all_items = redis_client.lrange("celery", 0, -1)
        items_to_keep = []
        for raw in all_items:
            try:
                item_data = json.loads(raw)
                task_tenant_id = None
                task_args = None
                body_b64 = item_data.get("body")
                if body_b64:
                    body_json = json.loads(base64.b64decode(body_b64).decode("utf-8"))
                    if isinstance(body_json, list) and body_json:
                        args = body_json[0]
                        task_args = args
                        if len(args) > 3:
                            task_tenant_id = args[3]
                if task_tenant_id != api_key.tenant_id:
                    items_to_keep.append(raw)
                else:
                    purged_count += 1
                    if task_args and len(task_args) >= 3:
                        undo_tasks.append({
                            "target_id": task_args[0], "domain": task_args[1],
                            "scan_types": task_args[2], "tenant_id": task_tenant_id,
                        })
            except Exception:
                items_to_keep.append(raw)

        if purged_count > 0:
            pipe = redis_client.pipeline()
            pipe.delete("celery")
            for item in items_to_keep:
                pipe.rpush("celery", item)
            pipe.execute()

    revoked_count = 0
    i = celery_app.control.inspect(timeout=5.0)
    if i:
        for tasks in list((i.reserved() or {}).values()) + list((i.active() or {}).values()):
            for task in tasks:
                if extract_tenant_from_task(task) == api_key.tenant_id:
                    mark_task_cancelled(task.get("id"))
                    celery_app.control.revoke(task.get("id"), terminate=True)
                    revoked_count += 1

    zombies = session.exec(
        select(Target).where(
            and_(
                Target.tenant_id == api_key.tenant_id,
                or_(Target.scan_status == "queued", Target.scan_status == "running"),
            )
        )
    ).all()
    for z in zombies:
        z.scan_status = "idle"
        z.scan_progress = "Stopped by API purge"
        session.add(z)
    session.commit()

    undo_batch_id = None
    if undo_tasks:
        undo_batch_id = _uuid.uuid4().hex[:12]
        redis_client.setex(f"yads:undo_purge:{undo_batch_id}", 60, json.dumps(undo_tasks))

    return {
        "purged_count": purged_count,
        "revoked_count": revoked_count,
        "reset_count": len(zombies),
        "undo_batch": undo_batch_id,
    }


class UndoPurgeRequest(BaseModel):
    undo_batch: str


@router.post("/queue/undo-purge")
async def undo_purge_queue(
    payload: UndoPurgeRequest,
    api_key: Annotated[APIKey, Depends(get_api_key)],
):
    key = f"yads:undo_purge:{payload.undo_batch}"
    raw = redis_client.get(key)
    if not raw:
        raise HTTPException(status_code=404, detail="Undo window expired or batch not found")

    tasks = json.loads(raw)
    requeued = 0
    for t in tasks:
        if t.get("tenant_id") != api_key.tenant_id:
            continue
        celery_app.send_task(
            "yads.worker.run_all_scans",
            args=[t["target_id"], t["domain"], t["scan_types"], t["tenant_id"]],
        )
        requeued += 1
    redis_client.delete(key)

    return {"requeued": requeued}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_v1_queue_purge.py -v`
Expected: FAIL with `404 Not Found` until the router is registered in Task 8 — same note as Task 3 Step 4. Proceed to commit; full pass is confirmed in Task 8.

- [ ] **Step 5: Commit**

```bash
git add yads/api/routers/v1_queue.py tests/test_v1_queue_purge.py
git commit -m "feat: add destructive-scoped queue purge/undo-purge endpoints"
```

---

### Task 5: `v1_tags.py`

**Files:**
- Create: `yads/api/routers/v1_tags.py`
- Test: `tests/test_v1_tags.py`

**Interfaces:**
- Consumes: `get_api_key`, `RequireScope` (`yads/auth/deps.py`); `get_session` (`yads/database.py`); `get_unique_tags(session, tenant_id=None) -> List[str]` (`yads/api/routers/tags.py`, module-level function).
- Produces: `router = APIRouter(prefix="/api/v1", tags=["API v1 — Tags"])` with routes `GET /api/v1/tags`, `POST /api/v1/targets/{target_id}/tags`, `DELETE /api/v1/targets/{target_id}/tags/{tag}`, `POST /api/v1/tags/bulk-assign`, `POST /api/v1/targets/bulk/tag`, `DELETE /api/v1/tags/{tag_name}`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_v1_tags.py
"""Covers the full tags surface: list, per-target add/remove, bulk
assign/add, and global delete -- all API-key-authenticated and
tenant-scoped."""

import pytest


@pytest.fixture
def owned_target(db_session, test_tenant):
    from yads.models import Target
    from sqlmodel import select

    existing = db_session.exec(
        select(Target).where(Target.domain == "v1-tags-fixture.example.com")
    ).first()
    if existing:
        return existing
    target = Target(domain="v1-tags-fixture.example.com", tenant_id=test_tenant.id, tags=[])
    db_session.add(target)
    db_session.commit()
    db_session.refresh(target)
    return target


def test_tags_list_requires_api_key(client):
    r = client.get("/api/v1/tags")
    assert r.status_code == 401


def test_tags_list_returns_list(api_key_client):
    r = api_key_client.get("/api/v1/tags")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_add_and_remove_tag_on_target(api_key_client, owned_target):
    r = api_key_client.post(f"/api/v1/targets/{owned_target.id}/tags", json={"tag": "sedoparking"})
    assert r.status_code == 200
    assert "sedoparking" in r.json()

    r = api_key_client.delete(f"/api/v1/targets/{owned_target.id}/tags/sedoparking")
    assert r.status_code == 200
    assert "sedoparking" not in r.json()


def test_add_tag_on_other_tenant_target_returns_404(api_key_client, db_session):
    from yads.models import Target, Tenant

    other_tenant = Tenant(name="Other Tenant For Tags Test", slug="other-tenant-tags")
    db_session.add(other_tenant)
    db_session.commit()
    db_session.refresh(other_tenant)

    other_target = Target(domain="other-tenant-target.example.com", tenant_id=other_tenant.id, tags=[])
    db_session.add(other_target)
    db_session.commit()
    db_session.refresh(other_target)

    r = api_key_client.post(f"/api/v1/targets/{other_target.id}/tags", json={"tag": "sedoparking"})
    assert r.status_code == 404


def test_bulk_assign_add_action(api_key_client, owned_target):
    r = api_key_client.post("/api/v1/tags/bulk-assign", json={
        "target_ids": [owned_target.id], "tags": ["bulk-tag-a"], "action": "add",
    })
    assert r.status_code == 200
    assert r.json()["updated"] == 1


def test_bulk_add_by_ids(api_key_client, owned_target):
    r = api_key_client.post("/api/v1/targets/bulk/tag", json={
        "target_ids": [owned_target.id], "tag": "bulk-tag-b",
    })
    assert r.status_code == 200
    assert r.json()["updated"] >= 1


def test_delete_tag_globally_requires_destructive_scope(client, db_session, test_tenant):
    from yads.models import APIKey
    from yads.auth.security import generate_api_key

    plain_key, prefix, key_hash = generate_api_key()
    key_row = APIKey(
        tenant_id=test_tenant.id, name="pytest-no-destructive-tags",
        key_prefix=prefix, key_hash=key_hash, scopes=["read", "write"],
    )
    db_session.add(key_row)
    db_session.commit()

    r = client.delete("/api/v1/tags/sedoparking", headers={"X-API-Key": plain_key})
    assert r.status_code == 403


def test_delete_tag_globally_with_destructive_scope(api_key_client, owned_target):
    api_key_client.post(f"/api/v1/targets/{owned_target.id}/tags", json={"tag": "delete-me-globally"})
    r = api_key_client.delete("/api/v1/tags/delete-me-globally")
    assert r.status_code == 200
    assert r.json()["removed_from"] >= 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_v1_tags.py -v`
Expected: FAIL with `404 Not Found` on every route.

- [ ] **Step 3: Create the router**

```python
# yads/api/routers/v1_tags.py
"""API-key-authenticated tagging surface for yads-mcp and other machine
clients. Tenant-scoped throughout -- a deliberate tightening versus the
cookie-session tags.py routes for add_tag/remove_tag/list_tags, which
currently have no tenant check at all (see
docs/superpowers/specs/2026-08-24-yads-mcp-foundation-design.md section 6).
"""

from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from yads.api.routers.tags import get_unique_tags
from yads.auth.deps import RequireScope, get_api_key
from yads.database import get_session
from yads.models import APIKey, Target

router = APIRouter(prefix="/api/v1", tags=["API v1 — Tags"])


@router.get("/tags")
async def list_tags(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(get_api_key)],
):
    return get_unique_tags(session, tenant_id=api_key.tenant_id)


class AddTagRequest(BaseModel):
    tag: str


@router.post("/targets/{target_id}/tags")
async def add_tag(
    target_id: int,
    payload: AddTagRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(get_api_key)],
):
    target = session.exec(
        select(Target).where(Target.id == target_id, Target.tenant_id == api_key.tenant_id)
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if payload.tag not in (target.tags or []):
        new_tags = list(target.tags or [])
        new_tags.append(payload.tag)
        target.tags = new_tags
        session.add(target)
        session.commit()
    return target.tags


@router.delete("/targets/{target_id}/tags/{tag}")
async def remove_tag(
    target_id: int,
    tag: str,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(get_api_key)],
):
    target = session.exec(
        select(Target).where(Target.id == target_id, Target.tenant_id == api_key.tenant_id)
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if tag in (target.tags or []):
        new_tags = [t for t in target.tags if t != tag]
        target.tags = new_tags
        session.add(target)
        session.commit()
    return target.tags


class BulkAssignRequest(BaseModel):
    target_ids: List[int]
    tags: List[str]
    action: str = "add"


@router.post("/tags/bulk-assign")
async def bulk_assign_tags(
    payload: BulkAssignRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(get_api_key)],
):
    if not payload.target_ids:
        raise HTTPException(status_code=400, detail="No target_ids provided")
    if payload.action not in ("add", "remove", "replace"):
        raise HTTPException(status_code=400, detail="action must be add, remove, or replace")

    targets = session.exec(
        select(Target).where(Target.id.in_(payload.target_ids), Target.tenant_id == api_key.tenant_id)
    ).all()

    updated = 0
    for target in targets:
        current = list(target.tags or [])
        if payload.action == "add":
            for tg in payload.tags:
                if tg not in current:
                    current.append(tg)
        elif payload.action == "remove":
            current = [tg for tg in current if tg not in payload.tags]
        else:
            current = list(payload.tags)
        target.tags = current
        session.add(target)
        updated += 1

    session.commit()
    return {"updated": updated, "action": payload.action}


class BulkAddByIdsRequest(BaseModel):
    target_ids: List[int]
    tag: str


@router.post("/targets/bulk/tag")
async def bulk_add_tag(
    payload: BulkAddByIdsRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(get_api_key)],
):
    if not payload.target_ids:
        raise HTTPException(status_code=400, detail="No target_ids provided")

    targets = session.exec(
        select(Target).where(Target.id.in_(payload.target_ids), Target.tenant_id == api_key.tenant_id)
    ).all()

    updated = 0
    for target in targets:
        curr_tags = target.tags or []
        if payload.tag not in curr_tags:
            new_tags = list(curr_tags)
            new_tags.append(payload.tag)
            target.tags = new_tags
            session.add(target)
            updated += 1

    session.commit()
    return {"updated": updated, "tag": payload.tag}


@router.delete("/tags/{tag_name}", dependencies=[Depends(RequireScope("destructive"))])
async def delete_tag_globally(
    tag_name: str,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(get_api_key)],
):
    targets = session.exec(
        select(Target).where(Target.tags.contains([tag_name]), Target.tenant_id == api_key.tenant_id)
    ).all()

    removed_from = 0
    for target in targets:
        new_tags = [tg for tg in (target.tags or []) if tg != tag_name]
        if len(new_tags) != len(target.tags or []):
            target.tags = new_tags
            session.add(target)
            removed_from += 1

    session.commit()
    return {"tag": tag_name, "removed_from": removed_from}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_v1_tags.py -v`
Expected: FAIL with `404 Not Found` until Task 8 registers the router — same note as Task 3. Proceed to commit.

- [ ] **Step 5: Commit**

```bash
git add yads/api/routers/v1_tags.py tests/test_v1_tags.py
git commit -m "feat: add API-key-authenticated tagging endpoints"
```

---

### Task 6: `v1.py` scope tightening + `v1_scan.py` — single-target trigger

**Files:**
- Modify: `yads/api/routers/v1.py`
- Create: `yads/api/routers/v1_scan.py`
- Test: `tests/test_v1_scan_trigger.py`

**Interfaces:**
- Consumes: `RequireScope`, `get_api_key` (`yads/auth/deps.py`); `get_session` (`yads/database.py`); `REGISTRY` (`yads/core/module_registry.py`); `get_max_concurrent_scans(session) -> int`, `get_active_scan_count(session) -> int` (`yads/core/scheduler.py`); `celery_app` (`yads/worker.py`).
- Produces: `router = APIRouter(prefix="/api/v1", tags=["API v1 — Scanning"])` in `v1_scan.py` with `POST /api/v1/targets/{target_id}/scan`. Task 7 adds bulk-scan routes to this same router.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_v1_scan_trigger.py
"""Covers the existing /api/v1/dast/scan route's new scope requirement,
and the new per-target-id scan trigger."""

import pytest


@pytest.fixture
def scan_target(db_session, test_tenant):
    from yads.models import Target
    from sqlmodel import select

    existing = db_session.exec(
        select(Target).where(Target.domain == "v1-scan-fixture.example.com")
    ).first()
    if existing:
        return existing
    target = Target(domain="v1-scan-fixture.example.com", tenant_id=test_tenant.id, tags=[])
    db_session.add(target)
    db_session.commit()
    db_session.refresh(target)
    return target


def test_dast_scan_requires_scan_execute_scope(client, db_session, test_tenant):
    from yads.models import APIKey
    from yads.auth.security import generate_api_key

    plain_key, prefix, key_hash = generate_api_key()
    key_row = APIKey(
        tenant_id=test_tenant.id, name="pytest-no-scan-execute",
        key_prefix=prefix, key_hash=key_hash, scopes=["read", "write"],
    )
    db_session.add(key_row)
    db_session.commit()

    r = client.post(
        "/api/v1/dast/scan",
        json={"target_url": "https://scope-check.example.com"},
        headers={"X-API-Key": plain_key},
    )
    assert r.status_code == 403


def test_scan_trigger_by_target_id(api_key_client, scan_target):
    r = api_key_client.post(f"/api/v1/targets/{scan_target.id}/scan", json={"scan_types": ["ssl_scanner"]})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "queued"
    assert body["target_id"] == scan_target.id


def test_scan_trigger_rejects_invalid_scan_types(api_key_client, scan_target):
    r = api_key_client.post(f"/api/v1/targets/{scan_target.id}/scan", json={"scan_types": ["not-a-real-module"]})
    assert r.status_code == 400


def test_scan_trigger_other_tenant_target_returns_404(api_key_client, db_session):
    from yads.models import Target, Tenant

    other_tenant = Tenant(name="Other Tenant For Scan Test", slug="other-tenant-scan")
    db_session.add(other_tenant)
    db_session.commit()
    db_session.refresh(other_tenant)

    other_target = Target(domain="other-tenant-scan-target.example.com", tenant_id=other_tenant.id, tags=[])
    db_session.add(other_target)
    db_session.commit()
    db_session.refresh(other_target)

    r = api_key_client.post(f"/api/v1/targets/{other_target.id}/scan", json={"scan_types": ["ssl_scanner"]})
    assert r.status_code == 404
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_v1_scan_trigger.py -v`
Expected: `test_dast_scan_requires_scan_execute_scope` FAILs (existing route currently accepts the request without `scan_execute`, so it does not 403 yet). The other three FAIL with `404 Not Found` (route doesn't exist).

- [ ] **Step 3: Tighten `v1.py`, create `v1_scan.py`**

In `yads/api/routers/v1.py`, change the decorator on the existing `trigger_dast_scan` route from:
```python
@router.post("/dast/scan", responses={400: {"description": "Invalid target URL"}})
```
to:
```python
from yads.auth.deps import get_api_key, RequireScope  # RequireScope added to this existing import line

@router.post(
    "/dast/scan",
    responses={400: {"description": "Invalid target URL"}},
    dependencies=[Depends(RequireScope("scan_execute"))],
)
```
(If `v1.py` already imports `get_api_key` from `yads.auth.deps` on its own line, just add `RequireScope` to that same import rather than adding a second import line.)

Create `yads/api/routers/v1_scan.py`:

```python
# yads/api/routers/v1_scan.py
"""API-key-authenticated scan-triggering surface for yads-mcp and other
machine clients. See
docs/superpowers/specs/2026-08-24-yads-mcp-foundation-design.md section 5.3.
"""

from datetime import datetime
from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from yads.auth.deps import RequireScope, get_api_key
from yads.core.module_registry import REGISTRY
from yads.core.scheduler import get_active_scan_count, get_max_concurrent_scans
from yads.database import get_session
from yads.models import APIKey, Target
from yads.worker import celery_app

router = APIRouter(prefix="/api/v1", tags=["API v1 — Scanning"])


class ScanTriggerRequest(BaseModel):
    scan_types: List[str]
    scan_priority: Optional[int] = None


@router.post("/targets/{target_id}/scan", dependencies=[Depends(RequireScope("scan_execute"))])
async def scan_trigger_by_target_id(
    target_id: int,
    payload: ScanTriggerRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(get_api_key)],
):
    target = session.exec(
        select(Target).where(Target.id == target_id, Target.tenant_id == api_key.tenant_id)
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if payload.scan_priority is not None:
        target.scan_priority = max(1, min(9, payload.scan_priority))

    valid_types = set(REGISTRY.keys()) | {"dns_cleanup", "full_scan"}
    selected_types = [t for t in payload.scan_types if t in valid_types]
    if not selected_types:
        raise HTTPException(status_code=400, detail="No valid scan types selected")

    if "full_scan" in selected_types:
        selected_types = [n for n in REGISTRY.keys() if n not in ("subdomain_scanner", "catchall_detector")]

    max_concurrent = get_max_concurrent_scans(session)
    if get_active_scan_count(session) >= max_concurrent:
        raise HTTPException(status_code=429, detail=f"Concurrent scan limit ({max_concurrent}) reached")

    celery_app.send_task(
        "yads.worker.run_all_scans",
        args=[target.id, target.domain, selected_types, api_key.tenant_id],
        priority=getattr(target, "scan_priority", 5),
    )

    target.scan_status = "queued"
    target.queued_at = datetime.utcnow()
    session.add(target)
    session.commit()

    return {"status": "queued", "target_id": target.id, "domain": target.domain, "scan_types": selected_types}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_v1_scan_trigger.py -v`
Expected: `test_dast_scan_requires_scan_execute_scope` now PASSes (`v1.py` change is already registered since `v1.router` is already included in `main.py`). The other three still FAIL with `404 Not Found` until Task 8 registers `v1_scan.router`. Proceed to commit.

- [ ] **Step 5: Commit**

```bash
git add yads/api/routers/v1.py yads/api/routers/v1_scan.py tests/test_v1_scan_trigger.py
git commit -m "feat: require scan_execute scope on dast/scan, add per-target scan trigger"
```

---

### Task 7: `v1_scan.py` — bulk scan endpoints

**Files:**
- Modify: `yads/api/routers/v1_scan.py`
- Test: `tests/test_v1_scan_bulk.py`

**Interfaces:**
- Consumes: `_parse_bulk_criteria`, `_build_bulk_criteria_query`, `_get_final_scan_types`, `_queue_single_bulk_target`, `_audit_scan_trigger` (`yads/api/routers/targets.py`, module-level functions, importable as-is — all take a `Session`/`User`-shaped first two args; a lightweight `_ApiKeyAsUser` shim is used since these helpers read `.tenant_id` off their second argument and `_audit_scan_trigger` reads `.username`/`.id`/`.tenant_id`).
- Produces: `GET /api/v1/targets/bulk-scan/preview-count`, `POST /api/v1/targets/bulk-scan`, `POST /api/v1/targets/bulk/scan` added to `v1_scan.router`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_v1_scan_bulk.py
"""Covers bulk-scan-by-criteria preview/submit and bulk-scan-by-selected-ids."""

import pytest


@pytest.fixture
def bulk_targets(db_session, test_tenant):
    from yads.models import Target
    from sqlmodel import select

    domains = ["bulk-fixture-1.example.com", "bulk-fixture-2.example.com"]
    targets = []
    for d in domains:
        existing = db_session.exec(select(Target).where(Target.domain == d)).first()
        if existing:
            targets.append(existing)
            continue
        t = Target(domain=d, tenant_id=test_tenant.id, tags=[])
        db_session.add(t)
        db_session.commit()
        db_session.refresh(t)
        targets.append(t)
    return targets


def test_bulk_preview_count(api_key_client, bulk_targets):
    r = api_key_client.get("/api/v1/targets/bulk-scan/preview-count")
    assert r.status_code == 200
    assert r.json()["count"] >= 2


def test_bulk_scan_by_criteria(api_key_client, bulk_targets):
    r = api_key_client.post("/api/v1/targets/bulk-scan", json={"scan_types": ["ssl_scanner"]})
    assert r.status_code == 200
    assert r.json()["queued_count"] >= 2


def test_bulk_scan_by_criteria_rejects_no_valid_types(api_key_client, bulk_targets):
    r = api_key_client.post("/api/v1/targets/bulk-scan", json={"scan_types": ["not-a-real-module"]})
    assert r.status_code == 400


def test_bulk_scan_selected(api_key_client, bulk_targets):
    ids = [t.id for t in bulk_targets]
    r = api_key_client.post("/api/v1/targets/bulk/scan", json={"target_ids": ids, "scan_types": ["ssl_scanner"]})
    assert r.status_code == 200
    assert r.json()["queued_count"] == len(ids)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_v1_scan_bulk.py -v`
Expected: FAIL with `404 Not Found` on every route.

- [ ] **Step 3: Add the bulk-scan endpoints**

Add these imports to the top of `yads/api/routers/v1_scan.py` (alongside Task 6's imports):

```python
from dataclasses import dataclass

from yads.api.routers.targets import (
    _audit_scan_trigger,
    _build_bulk_criteria_query,
    _get_final_scan_types,
    _parse_bulk_criteria,
    _queue_single_bulk_target,
)
```

Append to `yads/api/routers/v1_scan.py`:

```python
@dataclass
class _ApiKeyAsUser:
    """`_build_bulk_criteria_query`, `_queue_single_bulk_target`, and
    `_audit_scan_trigger` (targets.py) were written to take a `User` ORM
    object and read `.tenant_id`/`.username`/`.id` off it. An `APIKey` has
    `.tenant_id` but no `.username`; this shim adapts an APIKey into the
    minimal shape those functions actually touch, so their tenant-scoping
    logic can be reused verbatim instead of re-implemented here."""
    tenant_id: Optional[int]
    id: Optional[int] = None
    username: str = "api-key"


class BulkScanByCriteriaRequest(BaseModel):
    scan_types: List[str]
    only_roots: bool = False
    online_only: bool = False
    scanned_before: Optional[str] = None


@router.get("/targets/bulk-scan/preview-count")
async def bulk_scan_preview_count(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(get_api_key)],
    only_roots: bool = False,
    online_only: bool = False,
    scanned_before: Optional[str] = None,
):
    from sqlmodel import func as sqlfunc

    fake_user = _ApiKeyAsUser(tenant_id=api_key.tenant_id)
    parsed_only_roots, parsed_online_only, cutoff = _parse_bulk_criteria(only_roots, online_only, scanned_before)
    query = _build_bulk_criteria_query(
        session, fake_user, only_roots=parsed_only_roots, online_only=parsed_online_only, scanned_before=cutoff
    )
    count = session.exec(select(sqlfunc.count()).select_from(query.subquery())).one()
    return {"count": count}


@router.post("/targets/bulk-scan", dependencies=[Depends(RequireScope("scan_execute"))])
async def bulk_scan_by_criteria(
    payload: BulkScanByCriteriaRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(get_api_key)],
):
    fake_user = _ApiKeyAsUser(tenant_id=api_key.tenant_id)

    final_types = _get_final_scan_types(payload.scan_types)
    if not final_types:
        raise HTTPException(status_code=400, detail="No valid scan types selected")

    only_roots, online_only, cutoff = _parse_bulk_criteria(
        payload.only_roots, payload.online_only, payload.scanned_before
    )
    query = _build_bulk_criteria_query(session, fake_user, only_roots=only_roots, online_only=online_only, scanned_before=cutoff)
    matched_ids = session.exec(query).all()

    count = 0
    for tid in matched_ids:
        if _queue_single_bulk_target(session, fake_user, str(tid), final_types):
            count += 1
    session.commit()
    _audit_scan_trigger(session, None, [str(t) for t in matched_ids[:50]], final_types, "bulk_scan_by_criteria_api")

    return {"matched_count": len(matched_ids), "queued_count": count, "scan_types": final_types}


class BulkScanSelectedRequest(BaseModel):
    target_ids: List[int]
    scan_types: List[str]


@router.post("/targets/bulk/scan", dependencies=[Depends(RequireScope("scan_execute"))])
async def bulk_scan_selected(
    payload: BulkScanSelectedRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(get_api_key)],
):
    if not payload.target_ids:
        raise HTTPException(status_code=400, detail="No target_ids provided")

    fake_user = _ApiKeyAsUser(tenant_id=api_key.tenant_id)
    final_types = _get_final_scan_types(payload.scan_types)
    if not final_types:
        raise HTTPException(status_code=400, detail="No valid scan types selected")

    count = 0
    for tid in payload.target_ids:
        if _queue_single_bulk_target(session, fake_user, str(tid), final_types):
            count += 1
    session.commit()
    _audit_scan_trigger(session, None, [str(t) for t in payload.target_ids[:50]], final_types, "bulk_scan_selected_api")

    return {"requested_count": len(payload.target_ids), "queued_count": count, "scan_types": final_types}
```

Note: `_audit_scan_trigger`'s `user` parameter is used as `user.username if user else "system"` / `user.id if user else None` / `user.tenant_id if user else None` — passing `None` here (rather than `fake_user`) means the audit log records `tenant_id=None` for API-key-triggered bulk scans, which is a real gap (loses attribution). This is flagged rather than silently worked around: `_audit_scan_trigger` takes a real `User`, and `_ApiKeyAsUser` deliberately doesn't extend it with a fake `.tenant_id`-only object being passed there, since that would silently misrepresent an API key as an authenticated user in the audit trail. A follow-up (out of scope for this plan) is to add an `api_key_id` column to `SecurityAuditLog` and thread it through; for now, API-key-triggered bulk scans are visible in `SecurityAuditLog.details` (via the `trigger` field's `_api` suffix) but not attributed to a specific key or tenant.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_v1_scan_bulk.py -v`
Expected: FAIL with `404 Not Found` until Task 8 registers the router. Proceed to commit.

- [ ] **Step 5: Commit**

```bash
git add yads/api/routers/v1_scan.py tests/test_v1_scan_bulk.py
git commit -m "feat: add bulk-scan-by-criteria and bulk-scan-selected API endpoints"
```

---

### Task 8: Register the new routers

**Files:**
- Modify: `yads/api/main.py:432-509` (the `app.include_router(...)` block) and its import line
- Test: none new — this task makes Tasks 3–7's existing tests pass for real

**Interfaces:**
- Consumes: `v1_queue.router`, `v1_tags.router`, `v1_scan.router` (Tasks 3–7).

- [ ] **Step 1: Confirm the pre-registration failures**

Run: `pytest tests/test_v1_queue_control.py tests/test_v1_queue_purge.py tests/test_v1_tags.py tests/test_v1_scan_trigger.py tests/test_v1_scan_bulk.py -v`
Expected: Every non-403/401 assertion still FAILs with `404 Not Found` (per the notes left in Tasks 3–7's Step 4) — this confirms the routers genuinely aren't registered yet, not that something else is broken.

- [ ] **Step 2: Register the routers**

In `yads/api/main.py`, extend the existing router import line (around line 424) — add `v1_queue, v1_tags, v1_scan` to the existing `from yads.api.routers import ...` line's list, e.g.:
```python
from yads.api.routers import analytics, auth, users, changelog, help, profile, queue, notifications, osint, tenant_settings, compliance, reports, ports, email_security, secrets, tech_drift, cert_timeline, asr, cloud_assets, search, setup, archived, workers, mobile, storage, metrics, report_builder, v1, v1_queue, v1_tags, v1_scan, pqc, security_findings, changes, attack_surface, scan_compare, scan_modules, scanner_import, scan_profiles, integrations, nuclei_suggestions, portfolio, executive_report, attack_path, ai_assistant, module_reports, waf_analysis, developer, onboarding, sysmetrics, discovery, addon_reports, third_party_domains, metadata_leaks, mitre_navigator, nis2_measures, dora_evidence, dormant_domains, compliance_wizard
```

Then, immediately after the existing `app.include_router(v1.router)` line, add:
```python
app.include_router(v1.router)
app.include_router(v1_queue.router)
app.include_router(v1_tags.router)
app.include_router(v1_scan.router)
```

- [ ] **Step 3: Run the full new-route test suite to verify it passes**

Run: `pytest tests/test_v1_queue_control.py tests/test_v1_queue_purge.py tests/test_v1_tags.py tests/test_v1_scan_trigger.py tests/test_v1_scan_bulk.py -v`
Expected: All PASS.

- [ ] **Step 4: Run the full existing test suite to check for regressions**

Run: `pytest tests/ -v`
Expected: All PASS (no regressions from the new imports/routers colliding with existing route prefixes — `/api/v1/queue/...`, `/api/v1/tags`, `/api/v1/targets/...` under the `v1_*` routers are new paths, not overlapping with `queue.router`'s `/queue/...` or `tags.router`'s `/targets/...`/`/api/tags` cookie-session paths).

- [ ] **Step 5: Commit**

```bash
git add yads/api/main.py
git commit -m "feat: register v1_queue, v1_tags, v1_scan routers"
```

---

### Task 9: `yads-mcp` repo skeleton

**Files:**
- Create (new repo, sibling to `yads`): `yads-mcp/pyproject.toml`, `yads-mcp/yads_mcp/__init__.py`, `yads-mcp/yads_mcp/client.py`
- Test: `yads-mcp/tests/test_client.py`

**Interfaces:**
- Produces: `yads_mcp.client.client() -> httpx.Client` reading `YADS_URL`/`YADS_API_KEY` env vars, raising `YadsConfigError` if either is missing. This is the sole interface every later task's tools call.

- [ ] **Step 1: Create the repo and write the failing test**

```bash
mkdir -p /home/mrmarco/Documents/gitlab/yads-project/yads-mcp/yads_mcp
mkdir -p /home/mrmarco/Documents/gitlab/yads-project/yads-mcp/tests
cd /home/mrmarco/Documents/gitlab/yads-project/yads-mcp
git init
```

```python
# yads-mcp/tests/test_client.py
"""Covers yads_mcp.client.client()'s env-var validation."""

import os
import pytest


def test_client_raises_without_yads_url(monkeypatch):
    monkeypatch.delenv("YADS_URL", raising=False)
    monkeypatch.setenv("YADS_API_KEY", "test-key")
    from yads_mcp.client import client, YadsConfigError
    with pytest.raises(YadsConfigError, match="YADS_URL"):
        client()


def test_client_raises_without_yads_api_key(monkeypatch):
    monkeypatch.setenv("YADS_URL", "http://localhost:8000")
    monkeypatch.delenv("YADS_API_KEY", raising=False)
    from yads_mcp.client import client, YadsConfigError
    with pytest.raises(YadsConfigError, match="YADS_API_KEY"):
        client()


def test_client_builds_httpx_client_with_correct_headers(monkeypatch):
    monkeypatch.setenv("YADS_URL", "http://localhost:8000")
    monkeypatch.setenv("YADS_API_KEY", "test-key")
    from yads_mcp.client import client
    c = client()
    assert c.headers["X-API-Key"] == "test-key"
    assert str(c.base_url) == "http://localhost:8000"
    c.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/mrmarco/Documents/gitlab/yads-project/yads-mcp && python -m pytest tests/test_client.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'yads_mcp'`

- [ ] **Step 3: Write the package**

```toml
# yads-mcp/pyproject.toml
[project]
name = "yads-mcp"
version = "0.1.0"
description = "MCP server wrapping YADS's API-key-authenticated /api/v1 surface for LLM agents"
requires-python = ">=3.10"
dependencies = [
    "mcp>=2.0.0,<3.0.0",
    "httpx>=0.27.0",
]

[project.optional-dependencies]
test = ["pytest>=7.0.0"]

[project.scripts]
yads-mcp = "yads_mcp.server:main"

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
include = ["yads_mcp*"]
```

```python
# yads-mcp/yads_mcp/__init__.py
```

```python
# yads-mcp/yads_mcp/client.py
"""Thin HTTP client for YADS's /api/v1 surface.

Authenticates with the X-API-Key header yads.auth.deps.get_api_key expects,
the same scoped-key pattern already used by the existing /api/v1/dast/scan
and /api/v1/findings routes.
"""

import os

import httpx


class YadsConfigError(RuntimeError):
    pass


def client() -> httpx.Client:
    url = os.environ.get("YADS_URL")
    api_key = os.environ.get("YADS_API_KEY")
    if not url:
        raise YadsConfigError("YADS_URL is not set (e.g. https://yads.example.com)")
    if not api_key:
        raise YadsConfigError("YADS_API_KEY is not set (create one via POST /api-keys/ with the scopes this agent needs)")
    return httpx.Client(base_url=url.rstrip("/"), headers={"X-API-Key": api_key}, timeout=30.0)
```

- [ ] **Step 4: Install in editable mode and run test to verify it passes**

Run:
```bash
cd /home/mrmarco/Documents/gitlab/yads-project/yads-mcp
python -m venv .venv
.venv/bin/pip install -e ".[test]"
.venv/bin/pytest tests/test_client.py -v
```
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
cd /home/mrmarco/Documents/gitlab/yads-project/yads-mcp
git add pyproject.toml yads_mcp/ tests/test_client.py .gitignore 2>/dev/null || git add pyproject.toml yads_mcp/ tests/test_client.py
git commit -m "feat: yads-mcp package skeleton with httpx client"
```
(If `.gitignore` doesn't exist yet, create one first with `.venv/`, `__pycache__/`, `*.egg-info/`, `.pytest_cache/` — one entry per line — then `git add` it too.)

---

### Task 10: `yads-mcp` tools — Queue & Scan Control

**Files:**
- Create: `yads-mcp/yads_mcp/server.py`
- Test: `yads-mcp/tests/conftest.py`, `yads-mcp/tests/test_queue_tools.py`

**Interfaces:**
- Consumes: `yads_mcp.client.client()` (Task 9); the yads endpoints from Tasks 3–4 (`/api/v1/queue/status`, `/api/v1/queue/control`, `/api/v1/queue/tasks/{id}/cancel`, `/api/v1/queue/purge`, `/api/v1/queue/undo-purge`).
- Produces: `mcp = MCPServer("yads")` and the first 7 `@mcp.tool()` functions: `queue_status`, `queue_pause`, `queue_resume`, `queue_cancel_task`, `queue_purge`, `queue_undo_purge`. `main()` entry point.

This task also creates the test conftest that every subsequent `yads-mcp` test task depends on — it points `yads_mcp.client.client` at the real `yads` app in-process, following `labcontrol_mcp/tests/conftest.py`'s exact pattern.

- [ ] **Step 1: Write the conftest and the failing test**

`yads-mcp` needs `yads` importable to run these tests in-process. Add `yads`'s own `requirements.txt`-installed environment as a test-only path, matching how `labcontrol_mcp`'s conftest inserts `REPO_ROOT` onto `sys.path`. Because `yads` requires the same Postgres/Redis test stack as `tests/conftest.py` in the `yads` repo (`docker-compose.test.yml`, ports 5433/6380), this conftest reuses that already-running stack rather than standing up a separate one.

```python
# yads-mcp/tests/conftest.py
"""Points yads_mcp.client at an in-process YADS FastAPI app (via Starlette's
TestClient, which bridges httpx's sync API the same way a real network
client would be used) instead of a real network address, and provisions a
throwaway API key with every Wave-1 scope -- so these tests exercise the
real request/response shapes without needing a separately-running YADS
deployment. Requires the same test Postgres/Redis stack as the yads repo's
own tests/conftest.py (docker-compose.test.yml, ports 5433/6380).
"""

import os
import sys
import uuid
from pathlib import Path

import pytest

YADS_REPO_ROOT = Path(__file__).resolve().parents[2] / "yads"
sys.path.insert(0, str(YADS_REPO_ROOT))

os.environ.setdefault("DATABASE_URL", "postgresql://yads_test:yads_test@localhost:5433/yads_test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6380/0")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-yads-testing-32chars!")
os.environ.setdefault("MFA_ENABLED", "false")
os.environ.setdefault("AUTH_MODE", "local")
os.environ.setdefault("METRICS_ENABLED", "false")
os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("LOG_DIR", "/tmp/yads-mcp-test-logs")
os.environ.setdefault("WORKER_MODE", "standalone")
os.environ.setdefault("YADS_ENCRYPTION_KEY", "test-encryption-key-bsi-compliant-123!")
os.environ.setdefault("YADS_ADMIN_USER", "admin")
os.environ.setdefault("YADS_ADMIN_PASS", "test-admin-password-for-yads-testing!")

from starlette.testclient import TestClient  # noqa: E402

from yads.api.main import app as yads_app  # noqa: E402
from yads.auth.security import create_access_token, generate_api_key  # noqa: E402

import yads_mcp.client as yads_client_module  # noqa: E402


@pytest.fixture(autouse=True)
def _patch_client(monkeypatch):
    login = TestClient(yads_app, raise_server_exceptions=False)

    from yads.database import engine
    from sqlmodel import Session, select
    from yads.models import Tenant, APIKey

    with Session(engine) as session:
        tenant = session.exec(select(Tenant).where(Tenant.slug == "yads-mcp-test-tenant")).first()
        if not tenant:
            tenant = Tenant(name="yads-mcp Test Tenant", slug="yads-mcp-test-tenant")
            session.add(tenant)
            session.commit()
            session.refresh(tenant)

        plain_key, prefix, key_hash = generate_api_key()
        key_row = APIKey(
            tenant_id=tenant.id,
            name=f"yads-mcp-test-{uuid.uuid4().hex[:8]}",
            key_prefix=prefix,
            key_hash=key_hash,
            scopes=["read", "write", "scan_execute", "destructive"],
        )
        session.add(key_row)
        session.commit()

    def _fake_client():
        return TestClient(yads_app, headers={"X-API-Key": plain_key}, raise_server_exceptions=False)

    monkeypatch.setattr(yads_client_module, "client", _fake_client)
    import yads_mcp.server as server_module
    monkeypatch.setattr(server_module, "client", _fake_client)
    yield
```

```python
# yads-mcp/tests/test_queue_tools.py
"""Covers the Queue & Scan Control tool group against the real (in-process)
YADS app -- see conftest.py for how yads_mcp.client is patched."""


def test_queue_status_tool_returns_shape():
    from yads_mcp.server import queue_status
    result = queue_status()
    for key in ("queue_active", "queued_count", "running_count"):
        assert key in result


def test_queue_pause_and_resume_tools():
    from yads_mcp.server import queue_pause, queue_resume

    result = queue_pause()
    assert result["queue_active"] is False

    result = queue_resume()
    assert result["queue_active"] is True


def test_queue_cancel_task_tool_not_found():
    from yads_mcp.server import queue_cancel_task
    import httpx
    with __import__("pytest").raises(httpx.HTTPStatusError):
        queue_cancel_task(task_id="nonexistent-task-id")


def test_queue_purge_requires_confirm():
    from yads_mcp.server import queue_purge
    result = queue_purge(confirm=True)
    assert "purged_count" in result


def test_queue_undo_purge_not_found():
    from yads_mcp.server import queue_undo_purge
    import httpx
    with __import__("pytest").raises(httpx.HTTPStatusError):
        queue_undo_purge(undo_batch="nonexistent-batch-id")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/mrmarco/Documents/gitlab/yads-project/yads-mcp && .venv/bin/pytest tests/test_queue_tools.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'yads_mcp.server'`

- [ ] **Step 3: Write `server.py`'s Queue & Scan Control group**

```python
# yads-mcp/yads_mcp/server.py
"""MCP server exposing YADS's API-key-authenticated /api/v1 surface as
tools, so any MCP-capable LLM agent can drive queue control, tagging, and
scanning operations without a human at the dashboard.

Run with: YADS_URL=https://yads.example.com YADS_API_KEY=<token> \
    python -m yads_mcp.server
"""

from mcp.server.mcpserver import MCPServer

from yads_mcp.client import client

mcp = MCPServer("yads")


# --- Queue & Scan Control ---


@mcp.tool()
def queue_status() -> dict:
    """Current queue state for this API key's tenant: whether the queue is
    active (paused/resumed), queued/running target counts, and the tenant's
    active/reserved Celery tasks."""
    with client() as c:
        resp = c.get("/api/v1/queue/status")
        resp.raise_for_status()
        return resp.json()


@mcp.tool()
def queue_pause() -> dict:
    """Pause the scan queue -- stops workers from picking up new tasks.
    NOTE: this is fleet-wide, not scoped to this key's tenant (matches
    YADS's existing dashboard pause behavior)."""
    with client() as c:
        resp = c.post("/api/v1/queue/control", json={"action": "pause"})
        resp.raise_for_status()
        return resp.json()


@mcp.tool()
def queue_resume() -> dict:
    """Resume the scan queue after a pause."""
    with client() as c:
        resp = c.post("/api/v1/queue/control", json={"action": "resume"})
        resp.raise_for_status()
        return resp.json()


@mcp.tool()
def queue_cancel_task(task_id: str) -> dict:
    """Cancel a single queued/reserved/active scan task by its Celery task
    id (see queue_status's active_tasks/reserved_tasks for ids). Only
    cancels tasks belonging to this key's tenant."""
    with client() as c:
        resp = c.post(f"/api/v1/queue/tasks/{task_id}/cancel")
        resp.raise_for_status()
        return resp.json()


@mcp.tool()
def queue_purge(confirm: bool) -> dict:
    """Clear every queued/running scan for this key's tenant -- irreversible
    beyond a 60-second undo window (see queue_undo_purge). Requires the
    'destructive' scope on this API key. Set confirm=True to actually
    perform this."""
    with client() as c:
        resp = c.post("/api/v1/queue/purge", json={"confirm": confirm})
        resp.raise_for_status()
        return resp.json()


@mcp.tool()
def queue_undo_purge(undo_batch: str) -> dict:
    """Re-queue the tasks purged by a prior queue_purge call, using the
    undo_batch id from that call's response. Only works within 60 seconds
    of the purge, and only for tasks that hadn't started running yet."""
    with client() as c:
        resp = c.post("/api/v1/queue/undo-purge", json={"undo_batch": undo_batch})
        resp.raise_for_status()
        return resp.json()


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/mrmarco/Documents/gitlab/yads-project/yads-mcp && .venv/bin/pip install -e ".[test]" && .venv/bin/pytest tests/test_queue_tools.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Commit**

```bash
cd /home/mrmarco/Documents/gitlab/yads-project/yads-mcp
git add yads_mcp/server.py tests/conftest.py tests/test_queue_tools.py
git commit -m "feat: add Queue & Scan Control MCP tools"
```

---

### Task 11: `yads-mcp` tools — Tagging & Organization

**Files:**
- Modify: `yads-mcp/yads_mcp/server.py`
- Test: `yads-mcp/tests/test_tags_tools.py`

**Interfaces:**
- Consumes: `client()` (Task 9); the yads endpoints from Task 5.
- Produces: 6 more `@mcp.tool()` functions: `tags_list`, `tags_add_to_target`, `tags_remove_from_target`, `tags_bulk_assign`, `tags_bulk_add_by_ids`, `tags_delete_globally`.

- [ ] **Step 1: Write the failing test**

```python
# yads-mcp/tests/test_tags_tools.py
"""Covers the Tagging & Organization tool group."""

import pytest


@pytest.fixture
def owned_target_id():
    import yads_mcp.server as server_module
    with server_module.client() as c:
        # Create a target the same way YADS's own dast/scan route does --
        # find-or-create by domain via a scan trigger is heavier than needed
        # here, so create directly via the DB the way the yads repo's own
        # test fixtures do.
        pass
    from yads.database import engine
    from sqlmodel import Session, select
    from yads.models import Target, Tenant

    with Session(engine) as session:
        tenant = session.exec(select(Tenant).where(Tenant.slug == "yads-mcp-test-tenant")).first()
        existing = session.exec(select(Target).where(Target.domain == "yads-mcp-tags-fixture.example.com")).first()
        if existing:
            return existing.id
        target = Target(domain="yads-mcp-tags-fixture.example.com", tenant_id=tenant.id, tags=[])
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


def test_tags_list_tool():
    from yads_mcp.server import tags_list
    result = tags_list()
    assert isinstance(result, list)


def test_tags_add_and_remove_tool(owned_target_id):
    from yads_mcp.server import tags_add_to_target, tags_remove_from_target

    result = tags_add_to_target(target_id=owned_target_id, tag="sedoparking")
    assert "sedoparking" in result

    result = tags_remove_from_target(target_id=owned_target_id, tag="sedoparking")
    assert "sedoparking" not in result


def test_tags_bulk_assign_tool(owned_target_id):
    from yads_mcp.server import tags_bulk_assign
    result = tags_bulk_assign(target_ids=[owned_target_id], tags=["bulk-tag"], action="add")
    assert result["updated"] == 1


def test_tags_bulk_add_by_ids_tool(owned_target_id):
    from yads_mcp.server import tags_bulk_add_by_ids
    result = tags_bulk_add_by_ids(target_ids=[owned_target_id], tag="bulk-tag-2")
    assert result["updated"] >= 1


def test_tags_delete_globally_tool(owned_target_id):
    from yads_mcp.server import tags_add_to_target, tags_delete_globally
    tags_add_to_target(target_id=owned_target_id, tag="delete-me-via-mcp")
    result = tags_delete_globally(tag_name="delete-me-via-mcp")
    assert result["removed_from"] >= 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/mrmarco/Documents/gitlab/yads-project/yads-mcp && .venv/bin/pytest tests/test_tags_tools.py -v`
Expected: FAIL with `ImportError: cannot import name 'tags_list' from 'yads_mcp.server'`

- [ ] **Step 3: Add the tagging tool group**

Append to `yads-mcp/yads_mcp/server.py` (after the Queue & Scan Control group, before `def main():`):

```python
# --- Tagging & Organization ---


@mcp.tool()
def tags_list() -> list[str]:
    """All unique tags currently in use across this key's tenant's targets."""
    with client() as c:
        resp = c.get("/api/v1/tags")
        resp.raise_for_status()
        return resp.json()


@mcp.tool()
def tags_add_to_target(target_id: int, tag: str) -> list[str]:
    """Add a tag to one target. Returns the target's full tag list after
    the change."""
    with client() as c:
        resp = c.post(f"/api/v1/targets/{target_id}/tags", json={"tag": tag})
        resp.raise_for_status()
        return resp.json()


@mcp.tool()
def tags_remove_from_target(target_id: int, tag: str) -> list[str]:
    """Remove a tag from one target. Returns the target's full tag list
    after the change."""
    with client() as c:
        resp = c.delete(f"/api/v1/targets/{target_id}/tags/{tag}")
        resp.raise_for_status()
        return resp.json()


@mcp.tool()
def tags_bulk_assign(target_ids: list[int], tags: list[str], action: str = "add") -> dict:
    """Add, remove, or replace tags on multiple targets at once. action:
    "add" (default), "remove", or "replace" (replaces each target's entire
    tag list with `tags`)."""
    with client() as c:
        resp = c.post("/api/v1/tags/bulk-assign", json={"target_ids": target_ids, "tags": tags, "action": action})
        resp.raise_for_status()
        return resp.json()


@mcp.tool()
def tags_bulk_add_by_ids(target_ids: list[int], tag: str) -> dict:
    """Add a single tag to multiple targets by id (simpler variant of
    tags_bulk_assign for the common "add one tag to many targets" case)."""
    with client() as c:
        resp = c.post("/api/v1/targets/bulk/tag", json={"target_ids": target_ids, "tag": tag})
        resp.raise_for_status()
        return resp.json()


@mcp.tool()
def tags_delete_globally(tag_name: str) -> dict:
    """Remove a tag from every target in this key's tenant that has it --
    irreversible. Requires the 'destructive' scope on this API key."""
    with client() as c:
        resp = c.delete(f"/api/v1/tags/{tag_name}")
        resp.raise_for_status()
        return resp.json()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/mrmarco/Documents/gitlab/yads-project/yads-mcp && .venv/bin/pytest tests/test_tags_tools.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Commit**

```bash
cd /home/mrmarco/Documents/gitlab/yads-project/yads-mcp
git add yads_mcp/server.py tests/test_tags_tools.py
git commit -m "feat: add Tagging & Organization MCP tools"
```

---

### Task 12: `yads-mcp` tools — Scanning Execution + README

**Files:**
- Modify: `yads-mcp/yads_mcp/server.py`
- Create: `yads-mcp/README.md`
- Test: `yads-mcp/tests/test_scan_tools.py`

**Interfaces:**
- Consumes: `client()` (Task 9); the yads endpoints from Tasks 6–7 and the existing `/api/v1/findings`.
- Produces: 6 more `@mcp.tool()` functions completing the 19-tool Wave 1 surface: `scan_trigger`, `scan_trigger_by_target_id`, `scan_bulk_preview_count`, `scan_bulk_by_criteria`, `scan_bulk_selected`, `scan_get_findings`.

- [ ] **Step 1: Write the failing test**

```python
# yads-mcp/tests/test_scan_tools.py
"""Covers the Scanning Execution tool group -- the final piece of the
Wave 1 surface."""

import pytest


@pytest.fixture
def scan_target_id():
    from yads.database import engine
    from sqlmodel import Session, select
    from yads.models import Target, Tenant

    with Session(engine) as session:
        tenant = session.exec(select(Tenant).where(Tenant.slug == "yads-mcp-test-tenant")).first()
        existing = session.exec(select(Target).where(Target.domain == "yads-mcp-scan-fixture.example.com")).first()
        if existing:
            return existing.id
        target = Target(domain="yads-mcp-scan-fixture.example.com", tenant_id=tenant.id, tags=[])
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


def test_scan_trigger_tool():
    from yads_mcp.server import scan_trigger
    result = scan_trigger(target_url="https://yads-mcp-dast-fixture.example.com", profile="quick")
    assert result["status"] == "queued"


def test_scan_trigger_by_target_id_tool(scan_target_id):
    from yads_mcp.server import scan_trigger_by_target_id
    result = scan_trigger_by_target_id(target_id=scan_target_id, scan_types=["ssl_scanner"])
    assert result["status"] == "queued"


def test_scan_bulk_preview_count_tool(scan_target_id):
    from yads_mcp.server import scan_bulk_preview_count
    result = scan_bulk_preview_count()
    assert "count" in result


def test_scan_bulk_by_criteria_tool(scan_target_id):
    from yads_mcp.server import scan_bulk_by_criteria
    result = scan_bulk_by_criteria(scan_types=["ssl_scanner"])
    assert "queued_count" in result


def test_scan_bulk_selected_tool(scan_target_id):
    from yads_mcp.server import scan_bulk_selected
    result = scan_bulk_selected(target_ids=[scan_target_id], scan_types=["ssl_scanner"])
    assert result["queued_count"] == 1


def test_scan_get_findings_tool():
    from yads_mcp.server import scan_get_findings
    result = scan_get_findings()
    assert isinstance(result, list)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/mrmarco/Documents/gitlab/yads-project/yads-mcp && .venv/bin/pytest tests/test_scan_tools.py -v`
Expected: FAIL with `ImportError: cannot import name 'scan_trigger' from 'yads_mcp.server'`

- [ ] **Step 3: Add the scanning tool group**

Append to `yads-mcp/yads_mcp/server.py` (after the Tagging & Organization group, before `def main():`):

```python
# --- Scanning Execution ---


@mcp.tool()
def scan_trigger(target_url: str, profile: str = "standard") -> dict:
    """Trigger a scan for a URL, finding-or-creating the Target by domain.
    profile: "quick" (web_analyzer only), "standard" (dns_scanner,
    web_analyzer, ssl_scanner -- default), or "full" (every module except
    dns_cleanup)."""
    with client() as c:
        resp = c.post("/api/v1/dast/scan", json={"target_url": target_url, "profile": profile})
        resp.raise_for_status()
        return resp.json()


@mcp.tool()
def scan_trigger_by_target_id(target_id: int, scan_types: list[str], scan_priority: int | None = None) -> dict:
    """Trigger a scan for an already-known target by its numeric id, with
    an explicit module list (e.g. ["catchall_detector"] for a
    parked-domain-only check). scan_types accepts module names from the
    scanner registry, plus "full_scan" (expands to every module except
    subdomain_scanner and catchall_detector) and "dns_cleanup"."""
    body: dict = {"scan_types": scan_types}
    if scan_priority is not None:
        body["scan_priority"] = scan_priority
    with client() as c:
        resp = c.post(f"/api/v1/targets/{target_id}/scan", json=body)
        resp.raise_for_status()
        return resp.json()


@mcp.tool()
def scan_bulk_preview_count(only_roots: bool = False, online_only: bool = False, scanned_before: str | None = None) -> dict:
    """Count how many targets match a set of bulk-scan criteria, without
    queuing anything -- use before scan_bulk_by_criteria to see the blast
    radius first. scanned_before is an ISO date string ("2026-08-01");
    matches targets last scanned before that date OR never scanned."""
    params: dict = {"only_roots": only_roots, "online_only": online_only}
    if scanned_before:
        params["scanned_before"] = scanned_before
    with client() as c:
        resp = c.get("/api/v1/targets/bulk-scan/preview-count", params=params)
        resp.raise_for_status()
        return resp.json()


@mcp.tool()
def scan_bulk_by_criteria(
    scan_types: list[str],
    only_roots: bool = False,
    online_only: bool = False,
    scanned_before: str | None = None,
) -> dict:
    """Queue a scan for every target matching the given criteria (combined
    with AND). No target-tag filter exists yet -- to scan only targets
    without a given tag, list tags_list, resolve target ids yourself, and
    use scan_bulk_selected instead."""
    body: dict = {"scan_types": scan_types, "only_roots": only_roots, "online_only": online_only}
    if scanned_before:
        body["scanned_before"] = scanned_before
    with client() as c:
        resp = c.post("/api/v1/targets/bulk-scan", json=body)
        resp.raise_for_status()
        return resp.json()


@mcp.tool()
def scan_bulk_selected(target_ids: list[int], scan_types: list[str]) -> dict:
    """Queue a scan for an explicit list of target ids."""
    with client() as c:
        resp = c.post("/api/v1/targets/bulk/scan", json={"target_ids": target_ids, "scan_types": scan_types})
        resp.raise_for_status()
        return resp.json()


@mcp.tool()
def scan_get_findings() -> list[dict]:
    """All scan findings for this key's tenant, newest first."""
    with client() as c:
        resp = c.get("/api/v1/findings")
        resp.raise_for_status()
        return resp.json()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/mrmarco/Documents/gitlab/yads-project/yads-mcp && .venv/bin/pytest tests/ -v`
Expected: All PASS (Tasks 10–12's tests, run together, all green).

- [ ] **Step 5: Write the README**

```markdown
# yads-mcp

MCP server that lets any MCP-capable LLM agent (Claude Code, or another
agent process reachable over the same network as YADS) drive queue
control, tagging, and scan execution through YADS's own `/api/v1` API,
without a human at the dashboard.

It's a thin stdio wrapper around YADS's existing HTTP API
(`/api/v1/queue/*`, `/api/v1/tags*`, `/api/v1/targets/*`) — no separate
execution path, no bypassing tenant scoping or the scan-dispatch code
path. Every action taken through here is subject to the same tenant
isolation, concurrent-scan limits, and change-detection logic as the
dashboard.

## 1. Create an API key

From a machine already logged into YADS (session cookie), via
`/developer` or the `/api-keys/` endpoint, create a key with the scopes
this agent needs:

- `read` — status/list operations (queue_status, tags_list, scan_get_findings, ...)
- `write` — tag mutations
- `scan_execute` — triggering scans (single or bulk)
- `destructive` — queue_purge, tags_delete_globally (also requires
  `confirm=True` on the call itself)

Copy the returned token now — it is never shown again.

## 2. Install

```bash
cd yads-mcp
python -m venv .venv
.venv/bin/pip install -e .
```

### Tests

```bash
.venv/bin/pip install -e ".[test]"
.venv/bin/pytest tests/ -q
```

`tests/conftest.py` runs YADS in-process (Starlette `TestClient`) against
the same test Postgres/Redis stack as the `yads` repo's own tests
(`docker-compose.test.yml` in that repo, ports 5433/6380) — start that
stack first if these tests aren't passing.

## 3. Configure a client

Environment variables the server needs:

- `YADS_URL` — e.g. `https://yads.example.com`
- `YADS_API_KEY` — the token from step 1

### Claude Code

```bash
claude mcp add yads \
  --env YADS_URL=https://yads.example.com \
  --env YADS_API_KEY=<token> \
  -- /path/to/yads-mcp/.venv/bin/python -m yads_mcp.server
```

or add to `.mcp.json`:

```json
{
  "mcpServers": {
    "yads": {
      "command": "/path/to/yads-mcp/.venv/bin/python",
      "args": ["-m", "yads_mcp.server"],
      "env": {
        "YADS_URL": "https://yads.example.com",
        "YADS_API_KEY": "<token>"
      }
    }
  }
}
```

## Tools (Wave 1)

**Queue & Scan Control**
- `queue_status()`
- `queue_pause()` / `queue_resume()` — fleet-wide, not tenant-scoped
- `queue_cancel_task(task_id)`
- `queue_purge(confirm)` — destructive, tenant-scoped, 60s undo window
- `queue_undo_purge(undo_batch)`

**Tagging & Organization**
- `tags_list()`
- `tags_add_to_target(target_id, tag)` / `tags_remove_from_target(target_id, tag)`
- `tags_bulk_assign(target_ids, tags, action="add"|"remove"|"replace")`
- `tags_bulk_add_by_ids(target_ids, tag)`
- `tags_delete_globally(tag_name)` — destructive

**Scanning Execution**
- `scan_trigger(target_url, profile="standard")`
- `scan_trigger_by_target_id(target_id, scan_types, scan_priority=None)`
- `scan_bulk_preview_count(only_roots=False, online_only=False, scanned_before=None)`
- `scan_bulk_by_criteria(scan_types, only_roots=False, online_only=False, scanned_before=None)`
- `scan_bulk_selected(target_ids, scan_types)`
- `scan_get_findings()`

Waves 2–10 (Target/Asset Management, Reports & Export, Findings &
Compliance, OSINT/Discovery, Tenant/User Admin, Integrations, System/Infra
Admin) are tracked separately, each with its own design spec.
```

- [ ] **Step 6: Commit**

```bash
cd /home/mrmarco/Documents/gitlab/yads-project/yads-mcp
git add yads_mcp/server.py tests/test_scan_tools.py README.md
git commit -m "feat: add Scanning Execution MCP tools, complete Wave 1 surface"
```

---

## Self-Review Notes

- **Spec coverage:** §2 (scope) → Task 1. §3 (router surface) → Tasks 3, 5, 6, 8. §4 (export pattern) → explicitly out of scope per spec §9, no task needed. §5.1 → Tasks 3–4. §5.2 → Task 5. §5.3 → Tasks 6–7. §6 (inherited inconsistencies) → called out inline in Tasks 3 (pause/resume), 5 (tag tenant-scoping), 6 (scan_execute tightening). §7 (sedoparking follow-up) → not a task itself; the resulting tools (`queue_purge` + `scan_bulk_by_criteria`) are Tasks 4 and 7. §8 (repo skeleton) → Tasks 9–12.
- **New gap surfaced during planning, not in the spec:** `_audit_scan_trigger`'s existing signature only accepts a real `User`, not an API key — Task 7 flags this inline as a real audit-trail attribution gap rather than papering over it with a fake user object. Worth a follow-up task in a later wave (add `api_key_id` to `SecurityAuditLog`), not blocking for Wave 1.
- **Type consistency:** `ScanTriggerRequest.scan_types: List[str]` (Task 6) matches `BulkScanByCriteriaRequest.scan_types` and `BulkScanSelectedRequest.scan_types` (Task 7) and the MCP tool signatures in Task 12 — all `list[str]`. `APIKey.tenant_id: Optional[int]` is threaded consistently as `api_key.tenant_id` everywhere a tenant filter is applied.
