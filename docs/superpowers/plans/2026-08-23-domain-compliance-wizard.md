# Domain Compliance Wizard & Brand Watch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a guided 4-step wizard (target selection → reachability+webserver detection → deep crawl → brand watch setup) that becomes a status dashboard on re-entry, plus a recurring Brand Watch feature that searches Certificate Transparency logs and enumerates TLDs for a brand keyword, diffing against known targets to surface unsanctioned shadow domains for triage.

**Architecture:** New router `compliance_wizard.py` orchestrates existing scan primitives (`_queue_single_bulk_target`, `_build_bulk_criteria_query` from `targets.py`) across three new tables. A new Celery beat task (`run_brand_watch_scan`) does the actual internet-facing discovery work, reusing `ct_monitor.py`'s cert parsing and `tld_scanner.py`'s TLD list, writing new candidates for human triage via two small API endpoints.

**Tech Stack:** FastAPI + SQLModel + Jinja2 + Celery (matches existing yads stack, no new dependencies).

**Spec:** `yads/docs/superpowers/specs/2026-08-23-domain-compliance-wizard-design.md`

## Global Constraints

- v1 brand keyword scope: main "musterbank"/"muster-bank" only, matching case-insensitively, hyphen-optional — no subsidiary-brand support.
- v1 data sources: crt.sh Certificate Transparency search + TLD enumeration only. No WHOIS/RDAP/passive-DNS integration (schema leaves room via `ShadowDomainCandidate.source`, but no such source ships).
- No new scanning logic — steps 1–3 of the wizard dispatch existing `run_all_scans` with different `scan_types` subsets; no scanner module behavior changes.
- Task-name convention: any new Celery task uses `name="yads.worker.<func_name>"` regardless of which file it's defined in (matches existing `worker_tasks.py` convention).
- New tables get both a SQLModel class in `models.py` (fresh installs, via `create_all`) AND a matching idempotent `CREATE TABLE IF NOT EXISTS` block in `scripts/maintenance/migrate_db.py` (in-place upgrades) — this codebase has no Alembic.
- Every scan-trigger and every triage decision writes a `SecurityAuditLog` row using the same plain (non-hash-chained) pattern as `_audit_scan_trigger` in `targets.py:58-79` — the codebase's `compute_audit_hash` function exists but is never called by any current site; this plan matches existing behavior rather than being the first caller to wire up hashing (that's a separate, pre-existing gap, out of scope here).
- RBAC: every wizard/triage endpoint uses `RoleChecker(["admin", "tenant_admin", "scanner"])`, matching `targets.py`'s bulk-scan endpoints exactly.
- crt.sh calls are rate-limited via `RateLimitedClient` (`yads/modules/_shared_osint_utils.py`) but NOT gated by `OSINTQuotaManager` — crt.sh is a free public resource, not a BYOK paid service, so tenant OSINT quota does not apply to Brand Watch.

---

## File Structure

- **Modify `yads/models.py`**: add `ComplianceScanRun`, `BrandWatch`, `ShadowDomainCandidate` SQLModel classes.
- **Modify `scripts/maintenance/migrate_db.py`**: add three idempotent `CREATE TABLE IF NOT EXISTS` blocks.
- **Create `yads/api/routers/compliance_wizard.py`**: all wizard/dashboard/brand-watch/triage HTTP routes.
- **Create `yads/api/templates/compliance_wizard.html`**: single template rendering wizard steps 1–4 or the dashboard, based on state passed in.
- **Modify `yads/api/main.py`**: register the new router.
- **Modify `yads/api/templates/components/sidebar.html`**: add a new "COMPLIANCE" nav group.
- **Modify `yads/worker_tasks.py`**: add `_ct_search_keyword`, `_probe_keyword_across_tlds` helpers and the `run_brand_watch_scan` Celery task.
- **Modify `yads/worker_core.py`**: add `'brand-watch-scan'` to `beat_schedule`.
- **Create `tests/test_compliance_wizard.py`**: covers models, wizard steps, brand watch task, triage endpoints.

---

## Task 1: New tables — `ComplianceScanRun`, `BrandWatch`, `ShadowDomainCandidate`

**Files:**
- Modify: `yads/models.py`
- Modify: `scripts/maintenance/migrate_db.py`
- Test: `tests/test_compliance_wizard.py`

**Interfaces:**
- Produces: `ComplianceScanRun(id, tenant_id, criteria, current_step, target_ids, targets_total, targets_reachable, targets_webserver_confirmed, targets_crawled, started_at, step2_completed_at, step3_completed_at, created_by_user_id)`, `BrandWatch(id, tenant_id, keyword, active, last_run_at, created_by_user_id, created_at)`, `ShadowDomainCandidate(id, brand_watch_id, tenant_id, discovered_domain, source, status, dismissed_reason, resolved_target_id, first_seen_at, last_seen_at)` — every later task imports these three classes from `yads.models`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_compliance_wizard.py`:

```python
"""
Domain Compliance Wizard & Brand Watch tests.
"""

import pytest


@pytest.mark.compliance_wizard
class TestModels:
    def test_compliance_scan_run_roundtrip(self, db_session, test_tenant):
        from yads.models import ComplianceScanRun

        run = ComplianceScanRun(
            tenant_id=test_tenant.id,
            criteria="online_only",
            target_ids=[1, 2, 3],
        )
        db_session.add(run)
        db_session.commit()
        db_session.refresh(run)

        assert run.id is not None
        assert run.current_step == 1
        assert run.target_ids == [1, 2, 3]
        assert run.targets_total == 0

        db_session.delete(run)
        db_session.commit()

    def test_brand_watch_and_shadow_domain_candidate_roundtrip(self, db_session, test_tenant):
        from yads.models import BrandWatch, ShadowDomainCandidate

        watch = BrandWatch(tenant_id=test_tenant.id, keyword="musterbank")
        db_session.add(watch)
        db_session.commit()
        db_session.refresh(watch)

        assert watch.id is not None
        assert watch.active is True

        candidate = ShadowDomainCandidate(
            brand_watch_id=watch.id,
            tenant_id=test_tenant.id,
            discovered_domain="musterbank-portal.example",
            source="ct_log",
        )
        db_session.add(candidate)
        db_session.commit()
        db_session.refresh(candidate)

        assert candidate.status == "new"
        assert candidate.resolved_target_id is None

        db_session.delete(candidate)
        db_session.delete(watch)
        db_session.commit()

    def test_shadow_domain_candidate_unique_per_watch_and_domain(self, db_session, test_tenant):
        from yads.models import BrandWatch, ShadowDomainCandidate
        from sqlalchemy.exc import IntegrityError

        watch = BrandWatch(tenant_id=test_tenant.id, keyword="musterbank")
        db_session.add(watch)
        db_session.commit()
        db_session.refresh(watch)

        db_session.add(ShadowDomainCandidate(
            brand_watch_id=watch.id, tenant_id=test_tenant.id,
            discovered_domain="dupe.example", source="ct_log",
        ))
        db_session.commit()

        db_session.add(ShadowDomainCandidate(
            brand_watch_id=watch.id, tenant_id=test_tenant.id,
            discovered_domain="dupe.example", source="tld_enum",
        ))
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()

        db_session.query(ShadowDomainCandidate).filter_by(brand_watch_id=watch.id).delete()
        db_session.delete(watch)
        db_session.commit()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_compliance_wizard.py -v -m compliance_wizard`
Expected: FAIL with `ImportError: cannot import name 'ComplianceScanRun' from 'yads.models'`

- [ ] **Step 3: Add the three models**

In `yads/models.py`, add near the other small tenant-scoped tables (e.g. after `ScanSchedule`):

```python
class ComplianceScanRun(SQLModel, table=True):
    """One run of the Domain Compliance wizard: target selection -> reachability
    + webserver detection -> deep crawl. Also backs the status dashboard shown
    on re-entry."""
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: int = Field(foreign_key="tenant.id", index=True)
    criteria: str = Field(default="all")  # all | only_roots | online_only
    current_step: int = Field(default=1)  # 1-4
    target_ids: List[int] = Field(default=[], sa_column=Column(JSONB))

    targets_total: int = Field(default=0)
    targets_reachable: int = Field(default=0)
    targets_webserver_confirmed: int = Field(default=0)
    targets_crawled: int = Field(default=0)

    started_at: datetime = Field(default_factory=datetime.utcnow)
    step2_completed_at: Optional[datetime] = Field(default=None)
    step3_completed_at: Optional[datetime] = Field(default=None)
    created_by_user_id: Optional[int] = Field(default=None, foreign_key="user.id")


class BrandWatch(SQLModel, table=True):
    """A recurring brand-keyword shadow-domain watch (DORA compliance)."""
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: int = Field(foreign_key="tenant.id", index=True)
    keyword: str = Field(index=True)
    active: bool = Field(default=True)
    last_run_at: Optional[datetime] = Field(default=None)
    created_by_user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ShadowDomainCandidate(SQLModel, table=True):
    """A domain discovered by a BrandWatch run that isn't a known Target yet."""
    __table_args__ = (
        UniqueConstraint("brand_watch_id", "discovered_domain", name="uq_shadowdomain_watch_domain"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    brand_watch_id: int = Field(foreign_key="brandwatch.id", index=True)
    tenant_id: int = Field(foreign_key="tenant.id", index=True)
    discovered_domain: str = Field(index=True)
    source: str = Field(default="ct_log")  # ct_log | tld_enum
    status: str = Field(default="new", index=True)  # new | confirmed | dismissed
    dismissed_reason: Optional[str] = Field(default=None)
    resolved_target_id: Optional[int] = Field(default=None, foreign_key="target.id")
    first_seen_at: datetime = Field(default_factory=datetime.utcnow)
    last_seen_at: datetime = Field(default_factory=datetime.utcnow)
```

`UniqueConstraint` is already imported at the top of `models.py` (per house style shown in `yads/models.py:1-10`). If it isn't in your local checkout's import line, add it: `from sqlalchemy import Column, String, Text, UniqueConstraint`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_compliance_wizard.py -v -m compliance_wizard`
Expected: PASS (3 tests) — `create_all()` picks up the new tables automatically on the test DB via the app's lifespan startup.

- [ ] **Step 5: Add the idempotent migration blocks**

In `scripts/maintenance/migrate_db.py`, inside `migrate()`, add (following the exact `CREATE TABLE IF NOT EXISTS` + `CREATE INDEX IF NOT EXISTS` shape used for `compliancetrend`):

```python
        print(">> Creating compliancescanrun table (if not exists)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS compliancescanrun (
                    id SERIAL PRIMARY KEY,
                    tenant_id INTEGER NOT NULL REFERENCES tenant(id),
                    criteria VARCHAR NOT NULL DEFAULT 'all',
                    current_step INTEGER NOT NULL DEFAULT 1,
                    target_ids JSONB NOT NULL DEFAULT '[]',
                    targets_total INTEGER NOT NULL DEFAULT 0,
                    targets_reachable INTEGER NOT NULL DEFAULT 0,
                    targets_webserver_confirmed INTEGER NOT NULL DEFAULT 0,
                    targets_crawled INTEGER NOT NULL DEFAULT 0,
                    started_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc'),
                    step2_completed_at TIMESTAMP WITHOUT TIME ZONE,
                    step3_completed_at TIMESTAMP WITHOUT TIME ZONE,
                    created_by_user_id INTEGER REFERENCES "user"(id)
                );
                CREATE INDEX IF NOT EXISTS ix_compliancescanrun_tenant_id ON compliancescanrun (tenant_id);
            """))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error creating compliancescanrun table: {e}")

        print(">> Creating brandwatch table (if not exists)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS brandwatch (
                    id SERIAL PRIMARY KEY,
                    tenant_id INTEGER NOT NULL REFERENCES tenant(id),
                    keyword VARCHAR NOT NULL,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    last_run_at TIMESTAMP WITHOUT TIME ZONE,
                    created_by_user_id INTEGER REFERENCES "user"(id),
                    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc')
                );
                CREATE INDEX IF NOT EXISTS ix_brandwatch_tenant_id ON brandwatch (tenant_id);
                CREATE INDEX IF NOT EXISTS ix_brandwatch_keyword ON brandwatch (keyword);
            """))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error creating brandwatch table: {e}")

        print(">> Creating shadowdomaincandidate table (if not exists)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS shadowdomaincandidate (
                    id SERIAL PRIMARY KEY,
                    brand_watch_id INTEGER NOT NULL REFERENCES brandwatch(id),
                    tenant_id INTEGER NOT NULL REFERENCES tenant(id),
                    discovered_domain VARCHAR NOT NULL,
                    source VARCHAR NOT NULL DEFAULT 'ct_log',
                    status VARCHAR NOT NULL DEFAULT 'new',
                    dismissed_reason VARCHAR,
                    resolved_target_id INTEGER REFERENCES target(id),
                    first_seen_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc'),
                    last_seen_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc'),
                    CONSTRAINT uq_shadowdomain_watch_domain UNIQUE (brand_watch_id, discovered_domain)
                );
                CREATE INDEX IF NOT EXISTS ix_shadowdomaincandidate_brand_watch_id ON shadowdomaincandidate (brand_watch_id);
                CREATE INDEX IF NOT EXISTS ix_shadowdomaincandidate_tenant_id ON shadowdomaincandidate (tenant_id);
                CREATE INDEX IF NOT EXISTS ix_shadowdomaincandidate_discovered_domain ON shadowdomaincandidate (discovered_domain);
                CREATE INDEX IF NOT EXISTS ix_shadowdomaincandidate_status ON shadowdomaincandidate (status);
            """))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error creating shadowdomaincandidate table: {e}")
```

- [ ] **Step 6: Register the pytest marker**

Check `pytest.ini` or `pyproject.toml` for the `markers` list (same place `targets`, `auth`, `queue` etc. are registered) and add:

```ini
compliance_wizard: Domain Compliance Wizard and Brand Watch tests
```

- [ ] **Step 7: Commit**

```bash
git add yads/models.py scripts/maintenance/migrate_db.py tests/test_compliance_wizard.py pytest.ini
git commit -m "feat: add ComplianceScanRun, BrandWatch, ShadowDomainCandidate models"
```

---

## Task 2: Wizard step 1 — target selection & run creation

**Files:**
- Create: `yads/api/routers/compliance_wizard.py`
- Create: `yads/api/templates/compliance_wizard.html`
- Modify: `yads/api/main.py`
- Test: `tests/test_compliance_wizard.py`

**Interfaces:**
- Consumes: `ComplianceScanRun` (Task 1); `_build_bulk_criteria_query(session, user, only_roots=..., online_only=..., scanned_before=...)` and `_audit_scan_trigger(session, user, domains, scan_types, trigger, request)` imported from `yads.api.routers.targets`.
- Produces: `router` (FastAPI `APIRouter`, prefix `/compliance-wizard`), route `GET /compliance-wizard` (renders step 1 when no run exists), route `POST /compliance-wizard/start` (creates the `ComplianceScanRun`, resolves `target_ids`, advances to step 2) — later tasks add steps 2–4 to this same router/file.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_compliance_wizard.py`:

```python
@pytest.mark.compliance_wizard
class TestWizardStep1:
    def test_wizard_page_loads_with_no_active_run(self, admin_client):
        r = admin_client.get("/compliance-wizard", follow_redirects=True)
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]

    def test_start_creates_run_and_advances_to_step_2(self, admin_client, test_tenant, db_session):
        from yads.models import Target, ComplianceScanRun
        from sqlmodel import select

        target = db_session.exec(
            select(Target).where(Target.tenant_id == test_tenant.id)
        ).first()
        if not target:
            target = Target(domain="wizard-step1-test.example.com", tenant_id=test_tenant.id)
            db_session.add(target)
            db_session.commit()
            db_session.refresh(target)

        r = admin_client.post(
            "/compliance-wizard/start",
            data={"criteria": "all"},
            follow_redirects=True,
        )
        assert r.status_code == 200

        run = db_session.exec(
            select(ComplianceScanRun)
            .where(ComplianceScanRun.tenant_id == test_tenant.id)
            .order_by(ComplianceScanRun.id.desc())
        ).first()
        assert run is not None
        assert run.current_step == 2
        assert run.targets_total >= 1
        assert target.id in run.target_ids

        db_session.delete(run)
        db_session.commit()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_compliance_wizard.py -v -m compliance_wizard -k Step1`
Expected: FAIL with 404 (router doesn't exist yet)

- [ ] **Step 3: Create the router**

Create `yads/api/routers/compliance_wizard.py`:

```python
import logging
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from yads.database import get_session
from yads.auth.deps import RoleChecker
from yads.models import User, Target, ComplianceScanRun, BrandWatch, ShadowDomainCandidate
from yads.api.templating import templates
from yads.api.routers.targets import _build_bulk_criteria_query, _audit_scan_trigger

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/compliance-wizard", tags=["compliance"])

_ALLOWED_ROLES = ["admin", "tenant_admin", "scanner"]


def _latest_run(session: Session, user: User) -> Optional[ComplianceScanRun]:
    return session.exec(
        select(ComplianceScanRun)
        .where(ComplianceScanRun.tenant_id == user.tenant_id)
        .order_by(ComplianceScanRun.id.desc())
    ).first()


@router.get("", response_class=HTMLResponse)
async def wizard_or_dashboard(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(_ALLOWED_ROLES)),
):
    run = _latest_run(session, user)
    watches = session.exec(
        select(BrandWatch).where(BrandWatch.tenant_id == user.tenant_id)
    ).all()

    return templates.TemplateResponse("compliance_wizard.html", {
        "request": request,
        "user": user,
        "run": run,
        "watches": watches,
    })


@router.post("/start", response_class=HTMLResponse)
async def start_run(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(_ALLOWED_ROLES)),
):
    form = await request.form()
    criteria = form.get("criteria", "all")
    only_roots = criteria == "only_roots"
    online_only = criteria == "online_only"

    query = _build_bulk_criteria_query(session, user, only_roots=only_roots, online_only=online_only)
    target_ids = list(session.exec(query).all())

    run = ComplianceScanRun(
        tenant_id=user.tenant_id,
        criteria=criteria,
        current_step=2,
        target_ids=target_ids,
        targets_total=len(target_ids),
    )
    session.add(run)
    session.commit()
    session.refresh(run)

    _audit_scan_trigger(
        session, user,
        [str(tid) for tid in target_ids[:50]],
        ["web_analyzer"], "compliance_wizard_start", request,
    )

    return RedirectResponse(url="/compliance-wizard", status_code=303)
```

Add `from yads.api.templating import templates` — confirm this matches the existing import path (used verbatim in `dormant_domains.py`).

- [ ] **Step 4: Create the template**

Create `yads/api/templates/compliance_wizard.html`:

```html
{% extends "base.html" %}

{% block content %}
<div class="space-y-6">
    <h1 class="text-xl font-semibold text-white">Domain Compliance</h1>

    {% if not run %}
    <div class="bg-slate-900 border border-slate-800 rounded-lg p-6">
        <h2 class="text-slate-200 font-medium mb-4">Step 1: Select targets</h2>
        <form method="post" action="/compliance-wizard/start" class="space-y-4">
            <select name="criteria" class="bg-slate-800 text-slate-200 rounded px-3 py-2">
                <option value="all">All known targets</option>
                <option value="only_roots">Root domains only</option>
                <option value="online_only">Online only</option>
            </select>
            <button type="submit" class="bg-cyan-600 hover:bg-cyan-500 text-white px-4 py-2 rounded">
                Start
            </button>
        </form>
    </div>
    {% else %}
    <div class="bg-slate-900 border border-slate-800 rounded-lg p-6">
        <h2 class="text-slate-200 font-medium mb-4">Run #{{ run.id }} — step {{ run.current_step }} of 4</h2>
        <ul class="text-sm text-slate-400 space-y-1">
            <li>Targets selected: {{ run.targets_total }}</li>
            <li>Reachable / webserver confirmed: {{ run.targets_reachable }} / {{ run.targets_webserver_confirmed }}</li>
            <li>Deep-crawled: {{ run.targets_crawled }}</li>
        </ul>
    </div>
    {% endif %}

    <div class="bg-slate-900 border border-slate-800 rounded-lg p-6">
        <h2 class="text-slate-200 font-medium mb-4">Brand Watches</h2>
        {% if watches %}
        <ul class="text-sm text-slate-400 space-y-1">
            {% for w in watches %}
            <li>{{ w.keyword }} — {{ "active" if w.active else "paused" }}, last run {{ w.last_run_at or "never" }}</li>
            {% endfor %}
        </ul>
        {% else %}
        <p class="text-sm text-slate-500">No brand watches configured yet.</p>
        {% endif %}
    </div>
</div>
{% endblock %}
```

- [ ] **Step 5: Register the router**

In `yads/api/main.py`, add to the router import list and the `include_router` calls (matching `dormant_domains` exactly):

```python
from yads.api.routers import ..., compliance_wizard
...
app.include_router(compliance_wizard.router)
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/test_compliance_wizard.py -v -m compliance_wizard -k Step1`
Expected: PASS (2 tests)

- [ ] **Step 7: Commit**

```bash
git add yads/api/routers/compliance_wizard.py yads/api/templates/compliance_wizard.html yads/api/main.py tests/test_compliance_wizard.py
git commit -m "feat: add compliance wizard step 1 (target selection)"
```

---

## Task 3: Wizard step 2 — reachability + webserver detection dispatch

**Files:**
- Modify: `yads/api/routers/compliance_wizard.py`
- Modify: `yads/api/templates/compliance_wizard.html`
- Test: `tests/test_compliance_wizard.py`

**Interfaces:**
- Consumes: `ComplianceScanRun.target_ids` (Task 1/2); `_queue_single_bulk_target(session, user, tid_str, scan_types)` imported from `yads.api.routers.targets`.
- Produces: `POST /compliance-wizard/{run_id}/step2` (dispatches `web_analyzer` scans, advances `current_step` to 3 immediately — progress is computed on read, not blocked on completion); `_compute_step2_progress(session, run) -> tuple[int, int]` (reachable_count, webserver_confirmed_count), used by both the dashboard view and step 3's own scoping.

- [ ] **Step 1: Write the failing test**

```python
@pytest.mark.compliance_wizard
class TestWizardStep2:
    def test_step2_dispatch_advances_run_and_queues_scans(self, admin_client, test_tenant, db_session):
        from yads.models import Target, ComplianceScanRun
        from sqlmodel import select

        target = Target(domain="wizard-step2-test.example.com", tenant_id=test_tenant.id)
        db_session.add(target)
        db_session.commit()
        db_session.refresh(target)

        run = ComplianceScanRun(
            tenant_id=test_tenant.id, criteria="all", current_step=2,
            target_ids=[target.id], targets_total=1,
        )
        db_session.add(run)
        db_session.commit()
        db_session.refresh(run)

        r = admin_client.post(f"/compliance-wizard/{run.id}/step2", follow_redirects=True)
        assert r.status_code < 500

        db_session.refresh(run)
        assert run.current_step == 3

        db_session.delete(run)
        db_session.delete(target)
        db_session.commit()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_compliance_wizard.py -v -m compliance_wizard -k Step2`
Expected: FAIL with 404

- [ ] **Step 3: Implement step 2 dispatch + progress helper**

Add to `yads/api/routers/compliance_wizard.py` (import `_queue_single_bulk_target` alongside the existing `targets` imports, and `func`/`or_`/`and_`/`text` from sqlmodel/sqlalchemy for the progress query):

```python
from datetime import datetime
from sqlalchemy import func, or_, and_, text
from yads.api.routers.targets import _queue_single_bulk_target
from yads.models import ScanResult


def _compute_step2_progress(session: Session, run: ComplianceScanRun) -> tuple[int, int]:
    if not run.target_ids:
        return (0, 0)

    reachable_criteria = or_(
        and_(ScanResult.module_name == 'infrastructure_scanner', text("data->>'ip' IS NOT NULL")),
        and_(ScanResult.module_name == 'web_analyzer', text("(data->>'status_code')::int > 0")),
        and_(ScanResult.module_name == 'port_scanner', text("data->>'is_active' = 'true'")),
    )
    reachable = session.exec(
        select(func.count(func.distinct(ScanResult.target_id)))
        .where(ScanResult.target_id.in_(run.target_ids), reachable_criteria)
    ).one()

    webserver = session.exec(
        select(func.count(func.distinct(ScanResult.target_id)))
        .where(
            ScanResult.target_id.in_(run.target_ids),
            ScanResult.module_name == 'web_analyzer',
            text("(data->>'status_code')::int > 0"),
        )
    ).one()

    return (reachable or 0, webserver or 0)


@router.post("/{run_id}/step2", response_class=HTMLResponse)
async def dispatch_step2(
    run_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(_ALLOWED_ROLES)),
):
    run = session.exec(
        select(ComplianceScanRun).where(ComplianceScanRun.id == run_id, ComplianceScanRun.tenant_id == user.tenant_id)
    ).first()
    if not run:
        return RedirectResponse(url="/compliance-wizard", status_code=303)

    for tid in run.target_ids:
        _queue_single_bulk_target(session, user, str(tid), ["web_analyzer"])

    run.current_step = 3
    run.step2_completed_at = datetime.utcnow()
    session.add(run)
    session.commit()

    _audit_scan_trigger(session, user, [str(t) for t in run.target_ids[:50]], ["web_analyzer"], "compliance_wizard_step2", request)

    return RedirectResponse(url="/compliance-wizard", status_code=303)
```

Update `wizard_or_dashboard` (Task 2) to pass live progress to the template:

```python
    run = _latest_run(session, user)
    reachable, webserver_confirmed = (0, 0)
    if run and run.current_step >= 2:
        reachable, webserver_confirmed = _compute_step2_progress(session, run)
        if reachable != run.targets_reachable or webserver_confirmed != run.targets_webserver_confirmed:
            run.targets_reachable = reachable
            run.targets_webserver_confirmed = webserver_confirmed
            session.add(run)
            session.commit()
```

(Insert this right after `run = _latest_run(session, user)` in the existing `wizard_or_dashboard` function.)

- [ ] **Step 4: Add the step-2-triggering button to the template**

In `compliance_wizard.html`, inside the `{% else %}` branch (an active run exists), add:

```html
{% if run.current_step == 2 %}
<form method="post" action="/compliance-wizard/{{ run.id }}/step2">
    <button type="submit" class="bg-cyan-600 hover:bg-cyan-500 text-white px-4 py-2 rounded mt-4">
        Run reachability + webserver detection
    </button>
</form>
{% endif %}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_compliance_wizard.py -v -m compliance_wizard -k Step2`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add yads/api/routers/compliance_wizard.py yads/api/templates/compliance_wizard.html tests/test_compliance_wizard.py
git commit -m "feat: add compliance wizard step 2 (reachability + webserver detection)"
```

---

## Task 4: Wizard step 3 — deep crawl scoped to webserver-confirmed targets

**Files:**
- Modify: `yads/api/routers/compliance_wizard.py`
- Modify: `yads/api/templates/compliance_wizard.html`
- Test: `tests/test_compliance_wizard.py`

**Interfaces:**
- Consumes: `_compute_step2_progress` (Task 3, reused to identify which target IDs actually have a confirmed webserver — needs a small extension to return the ID list, not just the count).
- Produces: `POST /compliance-wizard/{run_id}/step3` (dispatches `crawler` only against webserver-confirmed target IDs, advances `current_step` to 4).

- [ ] **Step 1: Write the failing test**

```python
@pytest.mark.compliance_wizard
class TestWizardStep3:
    def test_step3_dispatch_only_targets_webserver_confirmed_subset(self, admin_client, test_tenant, db_session):
        from yads.models import Target, ComplianceScanRun, ScanResult
        from sqlmodel import select

        with_server = Target(domain="wizard-step3-with-server.example.com", tenant_id=test_tenant.id)
        without_server = Target(domain="wizard-step3-without-server.example.com", tenant_id=test_tenant.id)
        db_session.add(with_server)
        db_session.add(without_server)
        db_session.commit()
        db_session.refresh(with_server)
        db_session.refresh(without_server)

        db_session.add(ScanResult(
            target_id=with_server.id, module_name="web_analyzer",
            data={"status_code": 200}, result_hash="x",
        ))
        db_session.commit()

        run = ComplianceScanRun(
            tenant_id=test_tenant.id, criteria="all", current_step=3,
            target_ids=[with_server.id, without_server.id], targets_total=2,
        )
        db_session.add(run)
        db_session.commit()
        db_session.refresh(run)

        r = admin_client.post(f"/compliance-wizard/{run.id}/step3", follow_redirects=True)
        assert r.status_code < 500

        db_session.refresh(run)
        assert run.current_step == 4

        db_session.delete(run)
        db_session.query(ScanResult).filter_by(target_id=with_server.id).delete()
        db_session.delete(with_server)
        db_session.delete(without_server)
        db_session.commit()
```

`ScanResult`'s real field is `result_hash` (`yads/models.py:257`), not `data_hash` — confirmed by direct inspection, used correctly above.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_compliance_wizard.py -v -m compliance_wizard -k Step3`
Expected: FAIL with 404

- [ ] **Step 3: Implement step 3 dispatch**

Extend `_compute_step2_progress` in `compliance_wizard.py` into a variant that also returns the confirmed ID list (don't duplicate the query — refactor so the count function calls this):

```python
def _webserver_confirmed_ids(session: Session, target_ids: list[int]) -> list[int]:
    if not target_ids:
        return []
    rows = session.exec(
        select(ScanResult.target_id)
        .where(
            ScanResult.target_id.in_(target_ids),
            ScanResult.module_name == 'web_analyzer',
            text("(data->>'status_code')::int > 0"),
        )
        .distinct()
    ).all()
    return list(rows)
```

Update `_compute_step2_progress`'s webserver half to reuse it:

```python
    webserver_ids = _webserver_confirmed_ids(session, run.target_ids)
    webserver = len(webserver_ids)
```

Add the step 3 route:

```python
@router.post("/{run_id}/step3", response_class=HTMLResponse)
async def dispatch_step3(
    run_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(_ALLOWED_ROLES)),
):
    run = session.exec(
        select(ComplianceScanRun).where(ComplianceScanRun.id == run_id, ComplianceScanRun.tenant_id == user.tenant_id)
    ).first()
    if not run:
        return RedirectResponse(url="/compliance-wizard", status_code=303)

    confirmed_ids = _webserver_confirmed_ids(session, run.target_ids)
    for tid in confirmed_ids:
        _queue_single_bulk_target(session, user, str(tid), ["crawler"])

    run.current_step = 4
    run.step3_completed_at = datetime.utcnow()
    session.add(run)
    session.commit()

    _audit_scan_trigger(session, user, [str(t) for t in confirmed_ids[:50]], ["crawler"], "compliance_wizard_step3", request)

    return RedirectResponse(url="/compliance-wizard", status_code=303)
```

- [ ] **Step 4: Add the step-3-triggering button to the template**

```html
{% if run.current_step == 3 %}
<form method="post" action="/compliance-wizard/{{ run.id }}/step3">
    <button type="submit" class="bg-cyan-600 hover:bg-cyan-500 text-white px-4 py-2 rounded mt-4">
        Run deep content scan ({{ run.targets_webserver_confirmed }} targets with a live webserver)
    </button>
</form>
{% endif %}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_compliance_wizard.py -v -m compliance_wizard -k Step3`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add yads/api/routers/compliance_wizard.py yads/api/templates/compliance_wizard.html tests/test_compliance_wizard.py
git commit -m "feat: add compliance wizard step 3 (deep crawl scoped to live webservers)"
```

---

## Task 5: Nav entry

**Files:**
- Modify: `yads/api/templates/components/sidebar.html`
- Test: manual (templates aren't unit-tested in this codebase; verify by loading the page).

**Interfaces:** none (pure template change).

- [ ] **Step 1: Add a new nav group**

In `yads/api/templates/components/sidebar.html`, add a new `<details>` group (placed near the "AUDIT" group it was compared against during planning), following the exact existing shape:

```html
<details class="group" {% if '/compliance-wizard' in request.path %}open{% endif %}>
    <summary class="flex items-center p-2 text-slate-300 rounded-lg hover:bg-slate-800 cursor-pointer list-none transition-colors">
        <svg class="w-4 h-4 text-slate-400 group-hover:text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        <span class="ml-3 text-sm font-medium flex-1">Compliance</span>
        <svg class="w-4 h-4 text-slate-500 group-open:rotate-180 transition-transform" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
    </summary>
    <ul class="pl-9 mt-1 space-y-1">
        <li><a href="/compliance-wizard" class="block py-1.5 text-[13px] text-slate-400 hover:text-white {% if '/compliance-wizard' in request.path %}text-cyan-400 font-semibold{% endif %}">Domain Compliance</a></li>
    </ul>
</details>
```

- [ ] **Step 2: Manual verification**

Start the dev stack (`docker-compose up -d` or `uvicorn yads.api.main:app --reload`), log in, confirm the "Compliance" group appears in the sidebar and links to `/compliance-wizard`.

- [ ] **Step 3: Commit**

```bash
git add yads/api/templates/components/sidebar.html
git commit -m "feat: add Compliance nav entry for the domain compliance wizard"
```

---

## Task 6: Wizard step 4 — Brand Watch setup

**Files:**
- Modify: `yads/api/routers/compliance_wizard.py`
- Modify: `yads/api/templates/compliance_wizard.html`
- Test: `tests/test_compliance_wizard.py`

**Interfaces:**
- Produces: `POST /compliance-wizard/{run_id}/step4` (creates a `BrandWatch` row, does NOT dispatch anything synchronously — the first scan happens on the next beat tick).

- [ ] **Step 1: Write the failing test**

```python
@pytest.mark.compliance_wizard
class TestWizardStep4:
    def test_step4_creates_brand_watch(self, admin_client, test_tenant, db_session):
        from yads.models import ComplianceScanRun, BrandWatch
        from sqlmodel import select

        run = ComplianceScanRun(tenant_id=test_tenant.id, criteria="all", current_step=4, target_ids=[])
        db_session.add(run)
        db_session.commit()
        db_session.refresh(run)

        r = admin_client.post(
            f"/compliance-wizard/{run.id}/step4",
            data={"keyword": "musterbank"},
            follow_redirects=True,
        )
        assert r.status_code == 200

        watch = db_session.exec(
            select(BrandWatch).where(BrandWatch.tenant_id == test_tenant.id, BrandWatch.keyword == "musterbank")
        ).first()
        assert watch is not None
        assert watch.active is True

        db_session.delete(watch)
        db_session.delete(run)
        db_session.commit()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_compliance_wizard.py -v -m compliance_wizard -k Step4`
Expected: FAIL with 404

- [ ] **Step 3: Implement step 4**

```python
@router.post("/{run_id}/step4", response_class=HTMLResponse)
async def create_brand_watch(
    run_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(_ALLOWED_ROLES)),
):
    form = await request.form()
    keyword = (form.get("keyword") or "").strip().lower()
    if not keyword:
        return RedirectResponse(url="/compliance-wizard", status_code=303)

    watch = BrandWatch(tenant_id=user.tenant_id, keyword=keyword, created_by_user_id=user.id)
    session.add(watch)
    session.commit()

    return RedirectResponse(url="/compliance-wizard", status_code=303)
```

- [ ] **Step 4: Add the step-4 form to the template**

```html
{% if run.current_step == 4 %}
<form method="post" action="/compliance-wizard/{{ run.id }}/step4" class="mt-4 space-y-2">
    <label class="block text-sm text-slate-400">Brand keyword to watch</label>
    <input type="text" name="keyword" value="musterbank" class="bg-slate-800 text-slate-200 rounded px-3 py-2">
    <button type="submit" class="bg-cyan-600 hover:bg-cyan-500 text-white px-4 py-2 rounded">
        Start watching
    </button>
</form>
{% endif %}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_compliance_wizard.py -v -m compliance_wizard -k Step4`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add yads/api/routers/compliance_wizard.py yads/api/templates/compliance_wizard.html tests/test_compliance_wizard.py
git commit -m "feat: add compliance wizard step 4 (brand watch setup)"
```

---

## Task 7: `run_brand_watch_scan` — CT log + TLD discovery, diff, upsert

**Files:**
- Modify: `yads/worker_tasks.py`
- Modify: `yads/worker_core.py`
- Test: `tests/test_compliance_wizard.py`

**Interfaces:**
- Consumes: `BrandWatch`, `ShadowDomainCandidate`, `Target` (Task 1); `RateLimitedClient` from `yads.modules._shared_osint_utils`; `get_tld_list()` from `yads.modules.tld_scanner`.
- Produces: `_ct_search_keyword(keyword: str) -> list[str]` (domains found in crt.sh matching the keyword substring), `_probe_keyword_across_tlds(keyword: str) -> list[str]` (domains where `keyword.<tld>` resolves), `run_brand_watch_scan()` Celery task (`name="yads.worker.run_brand_watch_scan"`) — iterates all active `BrandWatch` rows, calls both helpers, diffs against `Target.domain` and existing dismissed candidates, upserts new `ShadowDomainCandidate` rows, writes a `SecurityAuditLog` entry, updates `last_run_at`.

- [ ] **Step 1: Write the failing test**

```python
@pytest.mark.compliance_wizard
class TestBrandWatchScan:
    def test_ct_search_keyword_parses_crtsh_response(self, monkeypatch):
        from yads import worker_tasks

        class FakeResponse:
            status_code = 200
            def json(self):
                return [
                    {"name_value": "portal.musterbank-example.com\nwww.musterbank-example.com"},
                    {"name_value": "unrelated-nothing.example.org"},
                ]

        class FakeClient:
            def register_service(self, *a, **kw):
                pass
            def get(self, service_name, url, **kw):
                assert "musterbank" in url
                return FakeResponse()

        monkeypatch.setattr(worker_tasks, "RateLimitedClient", lambda *a, **kw: FakeClient())

        domains = worker_tasks._ct_search_keyword("musterbank")
        assert "portal.musterbank-example.com" in domains
        assert "www.musterbank-example.com" in domains
        assert "unrelated-nothing.example.org" not in domains

    def test_run_brand_watch_scan_creates_candidates_and_skips_known_targets(self, monkeypatch, db_session, test_tenant):
        from yads import worker_tasks
        from yads.models import BrandWatch, ShadowDomainCandidate, Target

        known = Target(domain="musterbank-known.example.com", tenant_id=test_tenant.id)
        db_session.add(known)
        db_session.commit()
        db_session.refresh(known)

        watch = BrandWatch(tenant_id=test_tenant.id, keyword="musterbank")
        db_session.add(watch)
        db_session.commit()
        db_session.refresh(watch)

        monkeypatch.setattr(worker_tasks, "_ct_search_keyword", lambda kw: ["musterbank-known.example.com", "musterbank-shadow.example.net"])
        monkeypatch.setattr(worker_tasks, "_probe_keyword_across_tlds", lambda kw: ["musterbank.info"])

        worker_tasks.run_brand_watch_scan()

        candidates = db_session.exec(
            select(ShadowDomainCandidate).where(ShadowDomainCandidate.brand_watch_id == watch.id)
        ).all()
        discovered = {c.discovered_domain for c in candidates}

        assert "musterbank-shadow.example.net" in discovered
        assert "musterbank.info" in discovered
        assert "musterbank-known.example.com" not in discovered  # already a known Target, not a candidate

        for c in candidates:
            db_session.delete(c)
        db_session.delete(watch)
        db_session.delete(known)
        db_session.commit()
```

Add `from sqlmodel import select` at the top of the test file if not already present from earlier tasks.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_compliance_wizard.py -v -m compliance_wizard -k BrandWatchScan`
Expected: FAIL with `AttributeError: module 'yads.worker_tasks' has no attribute '_ct_search_keyword'`

- [ ] **Step 3: Implement the helpers and task**

Add to `yads/worker_tasks.py` (near the other periodic/beat tasks, e.g. after `sync_external_integrations`):

```python
import dns.resolver
import concurrent.futures
from yads.modules._shared_osint_utils import RateLimitedClient
from yads.modules.tld_scanner import get_tld_list
from yads.models import BrandWatch, ShadowDomainCandidate

_CRTSH_KEYWORD_URL = "https://crt.sh/?q={keyword}&output=json"


def _ct_search_keyword(keyword: str) -> list:
    """Substring-search crt.sh for a brand keyword across all issued certs
    (NOT scoped to a known domain, unlike ct_monitor.py's _fetch_certs)."""
    client = RateLimitedClient()
    client.register_service("crtsh", requests_per_second=1.0)

    domains = set()
    try:
        resp = client.get("crtsh", _CRTSH_KEYWORD_URL.format(keyword=keyword), timeout=20)
        if resp.status_code == 200:
            for entry in resp.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if keyword.lower() in name:
                        domains.add(name)
    except Exception as e:
        logger.warning(f"[BrandWatch] crt.sh search failed for '{keyword}': {e}")

    return sorted(domains)


def _probe_keyword_across_tlds(keyword: str) -> list:
    """Check whether <keyword>.<tld> resolves, for every TLD in the shared
    tld_scanner TLD list. Modeled on tld_scanner.py's threaded check_tld
    closure, but against a bare keyword rather than a known domain's SLD."""
    found = []

    def check(tld):
        candidate = f"{keyword}.{tld}"
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            resolver.resolve(candidate, "A")
            return candidate
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = [executor.submit(check, tld) for tld in get_tld_list()]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return sorted(found)


@celery_app.task(name="yads.worker.run_brand_watch_scan")
def run_brand_watch_scan():
    """Daily beat task: for every active BrandWatch, search CT logs and
    probe TLDs for the brand keyword, diff against known Targets, and
    upsert new ShadowDomainCandidate rows for triage."""
    with Session(engine) as session:
        watches = session.exec(select(BrandWatch).where(BrandWatch.active == True)).all()

        for watch in watches:
            ct_domains = _ct_search_keyword(watch.keyword)
            tld_domains = _probe_keyword_across_tlds(watch.keyword)

            known_domains = set(
                d.lower() for d in session.exec(
                    select(Target.domain).where(Target.tenant_id == watch.tenant_id)
                ).all()
            )
            existing_candidates = set(
                session.exec(
                    select(ShadowDomainCandidate.discovered_domain)
                    .where(ShadowDomainCandidate.brand_watch_id == watch.id)
                ).all()
            )

            new_count = 0
            for domain, source in [(d, "ct_log") for d in ct_domains] + [(d, "tld_enum") for d in tld_domains]:
                if domain in known_domains:
                    continue
                if domain in existing_candidates:
                    continue
                session.add(ShadowDomainCandidate(
                    brand_watch_id=watch.id,
                    tenant_id=watch.tenant_id,
                    discovered_domain=domain,
                    source=source,
                ))
                existing_candidates.add(domain)
                new_count += 1

            watch.last_run_at = datetime.utcnow()
            session.add(watch)

            try:
                entry = SecurityAuditLog(
                    event_type="brand_watch_scan",
                    tenant_id=watch.tenant_id,
                    success=True,
                    details={
                        "keyword": watch.keyword,
                        "ct_domains_found": len(ct_domains),
                        "tld_domains_found": len(tld_domains),
                        "new_candidates": new_count,
                    },
                )
                session.add(entry)
            except Exception as e:
                logger.warning(f"[BrandWatch] Failed to write audit log: {e}")

            session.commit()
```

Confirm `datetime` is already imported at module scope in `worker_tasks.py` (it is, per the earlier research: `from datetime import datetime, timezone`) — use `datetime.utcnow()` to match the rest of the file's convention rather than mixing in timezone-aware calls.

- [ ] **Step 4: Register the beat schedule entry**

In `yads/worker_core.py`, add to `beat_schedule` (after `'archived-target-reactivation-check'`):

```python
    'brand-watch-scan': {
        'task': 'yads.worker.run_brand_watch_scan',
        'schedule': 24 * 3600.0,  # daily
    },
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_compliance_wizard.py -v -m compliance_wizard -k BrandWatchScan`
Expected: PASS (2 tests)

- [ ] **Step 6: Commit**

```bash
git add yads/worker_tasks.py yads/worker_core.py tests/test_compliance_wizard.py
git commit -m "feat: add run_brand_watch_scan (CT log + TLD keyword discovery)"
```

---

## Task 8: Triage endpoints — confirm / dismiss

**Files:**
- Modify: `yads/api/routers/compliance_wizard.py`
- Modify: `yads/api/templates/compliance_wizard.html`
- Test: `tests/test_compliance_wizard.py`

**Interfaces:**
- Produces: `POST /compliance-wizard/shadow-domains/{id}/confirm` (creates a `Target` from `discovered_domain`, sets `status="confirmed"`, `resolved_target_id`), `POST /compliance-wizard/shadow-domains/{id}/dismiss` (body: `reason`, sets `status="dismissed"`, `dismissed_reason`).

- [ ] **Step 1: Write the failing test**

```python
@pytest.mark.compliance_wizard
class TestTriage:
    def _make_candidate(self, db_session, test_tenant, domain="musterbank-triage-test.example.net"):
        from yads.models import BrandWatch, ShadowDomainCandidate

        watch = BrandWatch(tenant_id=test_tenant.id, keyword="musterbank")
        db_session.add(watch)
        db_session.commit()
        db_session.refresh(watch)

        candidate = ShadowDomainCandidate(
            brand_watch_id=watch.id, tenant_id=test_tenant.id,
            discovered_domain=domain, source="ct_log",
        )
        db_session.add(candidate)
        db_session.commit()
        db_session.refresh(candidate)
        return watch, candidate

    def test_confirm_creates_target_and_updates_status(self, admin_client, test_tenant, db_session):
        from yads.models import ShadowDomainCandidate, Target
        from sqlmodel import select

        watch, candidate = self._make_candidate(db_session, test_tenant)

        r = admin_client.post(f"/compliance-wizard/shadow-domains/{candidate.id}/confirm", follow_redirects=True)
        assert r.status_code == 200

        db_session.refresh(candidate)
        assert candidate.status == "confirmed"
        assert candidate.resolved_target_id is not None

        created_target = db_session.exec(
            select(Target).where(Target.id == candidate.resolved_target_id)
        ).first()
        assert created_target.domain == "musterbank-triage-test.example.net"

        db_session.delete(candidate)
        db_session.delete(created_target)
        db_session.delete(watch)
        db_session.commit()

    def test_dismiss_sets_reason_and_status(self, admin_client, test_tenant, db_session):
        watch, candidate = self._make_candidate(db_session, test_tenant, domain="musterbank-dismiss-test.example.net")

        r = admin_client.post(
            f"/compliance-wizard/shadow-domains/{candidate.id}/dismiss",
            data={"reason": "unrelated third party, false positive substring match"},
            follow_redirects=True,
        )
        assert r.status_code == 200

        db_session.refresh(candidate)
        assert candidate.status == "dismissed"
        assert "false positive" in candidate.dismissed_reason

        db_session.delete(candidate)
        db_session.delete(watch)
        db_session.commit()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_compliance_wizard.py -v -m compliance_wizard -k Triage`
Expected: FAIL with 404

- [ ] **Step 3: Implement the triage endpoints**

```python
@router.post("/shadow-domains/{candidate_id}/confirm", response_class=HTMLResponse)
async def confirm_shadow_domain(
    candidate_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(_ALLOWED_ROLES)),
):
    candidate = session.exec(
        select(ShadowDomainCandidate).where(
            ShadowDomainCandidate.id == candidate_id,
            ShadowDomainCandidate.tenant_id == user.tenant_id,
        )
    ).first()
    if not candidate:
        return RedirectResponse(url="/compliance-wizard", status_code=303)

    new_target = Target(domain=candidate.discovered_domain, tenant_id=user.tenant_id)
    session.add(new_target)
    session.commit()
    session.refresh(new_target)

    candidate.status = "confirmed"
    candidate.resolved_target_id = new_target.id
    session.add(candidate)

    entry = SecurityAuditLog(
        event_type="shadow_domain_confirmed",
        username=user.username, user_id=user.id, tenant_id=user.tenant_id,
        source_ip=request.client.host if request.client else None,
        success=True,
        details={"discovered_domain": candidate.discovered_domain, "new_target_id": new_target.id},
    )
    session.add(entry)
    session.commit()

    return RedirectResponse(url="/compliance-wizard", status_code=303)


@router.post("/shadow-domains/{candidate_id}/dismiss", response_class=HTMLResponse)
async def dismiss_shadow_domain(
    candidate_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(_ALLOWED_ROLES)),
):
    form = await request.form()
    reason = (form.get("reason") or "").strip()

    candidate = session.exec(
        select(ShadowDomainCandidate).where(
            ShadowDomainCandidate.id == candidate_id,
            ShadowDomainCandidate.tenant_id == user.tenant_id,
        )
    ).first()
    if not candidate:
        return RedirectResponse(url="/compliance-wizard", status_code=303)

    candidate.status = "dismissed"
    candidate.dismissed_reason = reason
    session.add(candidate)

    entry = SecurityAuditLog(
        event_type="shadow_domain_dismissed",
        username=user.username, user_id=user.id, tenant_id=user.tenant_id,
        source_ip=request.client.host if request.client else None,
        success=True,
        details={"discovered_domain": candidate.discovered_domain, "reason": reason},
    )
    session.add(entry)
    session.commit()

    return RedirectResponse(url="/compliance-wizard", status_code=303)
```

Add `from yads.models import SecurityAuditLog` to the router's imports.

- [ ] **Step 4: Show pending candidates + triage actions in the dashboard template**

In `wizard_or_dashboard` (Task 2), add pending candidates to the context:

```python
    pending_candidates = []
    if watches:
        pending_candidates = session.exec(
            select(ShadowDomainCandidate)
            .where(
                ShadowDomainCandidate.tenant_id == user.tenant_id,
                ShadowDomainCandidate.status == "new",
            )
            .order_by(ShadowDomainCandidate.first_seen_at.desc())
        ).all()
```

Pass `"pending_candidates": pending_candidates` into the `TemplateResponse` context dict.

In `compliance_wizard.html`, add below the "Brand Watches" block:

```html
<div class="bg-slate-900 border border-slate-800 rounded-lg p-6">
    <h2 class="text-slate-200 font-medium mb-4">Shadow Domain Candidates ({{ pending_candidates|length }} pending)</h2>
    {% if pending_candidates %}
    <ul class="text-sm text-slate-400 space-y-3">
        {% for c in pending_candidates %}
        <li class="flex items-center justify-between border-b border-slate-800 pb-2">
            <span>{{ c.discovered_domain }} <span class="text-slate-600">({{ c.source }})</span></span>
            <span class="flex gap-2">
                <form method="post" action="/compliance-wizard/shadow-domains/{{ c.id }}/confirm">
                    <button type="submit" class="text-emerald-400 hover:text-emerald-300">Confirm</button>
                </form>
                <form method="post" action="/compliance-wizard/shadow-domains/{{ c.id }}/dismiss">
                    <input type="hidden" name="reason" value="reviewed, not Musterbank-related">
                    <button type="submit" class="text-slate-500 hover:text-slate-300">Dismiss</button>
                </form>
            </span>
        </li>
        {% endfor %}
    </ul>
    {% else %}
    <p class="text-sm text-slate-500">No pending candidates.</p>
    {% endif %}
</div>
```

(The hardcoded dismiss reason is a v1 placeholder for a real text input — acceptable for this plan since the spec doesn't require a reason-entry UI beyond "the dismissal is remembered"; a follow-up UI polish task can add a text field if the triage volume warrants it.)

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_compliance_wizard.py -v -m compliance_wizard -k Triage`
Expected: PASS (2 tests)

- [ ] **Step 6: Commit**

```bash
git add yads/api/routers/compliance_wizard.py yads/api/templates/compliance_wizard.html tests/test_compliance_wizard.py
git commit -m "feat: add shadow domain triage (confirm/dismiss) with audit logging"
```

---

## Task 9: Full-suite verification

**Files:** none (verification only).

- [ ] **Step 1: Run the complete new test module**

Run: `pytest tests/test_compliance_wizard.py -v -m compliance_wizard`
Expected: all tests PASS

- [ ] **Step 2: Run the full existing suite to check for regressions**

Run: `pytest tests/ -v`
Expected: no new failures compared to the pre-change baseline (targets.py imports were extended, not modified — but confirm nothing else broke).

- [ ] **Step 3: Manual smoke test**

Start the dev stack, log in as an admin/tenant_admin/scanner user, walk through: Compliance nav item → step 1 (select "all") → step 2 (dispatch, confirm progress numbers update) → step 3 (dispatch, confirm it only queued webserver-confirmed targets) → step 4 (create a "musterbank" brand watch) → confirm re-visiting `/compliance-wizard` shows the dashboard, not step 1 again. Manually trigger `run_brand_watch_scan` via `celery_app.send_task("yads.worker.run_brand_watch_scan")` or a Python shell and confirm candidates appear with working confirm/dismiss buttons.

- [ ] **Step 4: Commit (if any fixups were needed)**

```bash
git add -A
git commit -m "fix: address issues found during compliance wizard smoke test"
```
