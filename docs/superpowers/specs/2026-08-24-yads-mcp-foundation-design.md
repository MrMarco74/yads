# YADS MCP — Foundation Design

**Status:** Draft for review
**Scope:** Foundation (auth, conventions, package skeleton) + Wave 1 (Queue & Scan Control, Tagging & Organization, Scanning Execution)
**Owner decisions already made by user:**
- Build the full ~80-tool candidate surface eventually, phased across waves — not pruned down first. ("go for the full list... if we do it later or now makes no difference")
- New sibling repo `yads-mcp` (alongside `yads`, `yads-infra`, `yads-shadowtwin`), not a plugin inside `yads` and not folded into `labcontrol`.
- Destructive operations gated by a **new dedicated API-key scope** named `"destructive"` (single coarse-grained scope, not a `confirm:bool`-only mechanism — the scope is the authorization boundary, `confirm:bool` is a UX/safety belt-and-braces on top, matching `labcontrol_mcp`'s existing pattern of "no new concepts").
- Wave ordering: **Wave 1 = Queue & Scan Control + Tagging & Organization + Scanning Execution** (~19 tools). Waves 2–10 follow later, each its own spec→plan→implementation cycle.

This document covers the foundation every wave depends on, plus enough Wave 1 detail (real endpoint signatures) to make the first implementation plan concrete.

---

## 1. Why a separate repo, why a new API surface

YADS already has one API-key-authenticated surface: `yads/api/routers/v1.py`, mounted at `/api/v1`, using `get_api_key` (header `X-API-Key`, resolves to an `APIKey` row carrying `tenant_id` and `scopes`). Every other router (`queue.py`, `tags.py`, most of `targets.py`) is cookie-session-only (`get_current_user_html` / `RoleChecker`).

Two consequences that shape this design:

1. **New MCP-facing endpoints must live on the API-key surface, not be bolted onto the cookie-session routers.** Adding `Depends(get_api_key)` next to `Depends(get_current_user_html)` on an existing route (e.g. `queue.py`'s `purge_queue`) would mix two different session/tenant-resolution models in one function and make the existing HTML behavior harder to reason about. Instead, Wave 1 adds **new route files**, API-key-authenticated only, that call the same underlying logic (or, where that logic is entangled with HTML-only concerns like `RedirectResponse`, a thin re-implementation against the same DB/Celery operations).
2. **`yads-mcp` is a thin, separate process/repo.** It never touches the YADS database, Redis, or Celery broker directly — it only calls YADS's own HTTP API, exactly like `labcontrol_mcp` only calls LabControl's HTTP API. This keeps YADS's data-access invariants (tenant scoping, change-detection hashing, audit logging) in one place — the API — instead of duplicating them in a second codebase.

---

## 2. The `destructive` API-key scope

**File:** `yads/api/routers/api_keys.py:15`

```python
VALID_SCOPES = {"read", "write", "scan_execute", "provision_tenant"}
```

Add one entry:

```python
VALID_SCOPES = {"read", "write", "scan_execute", "provision_tenant", "destructive"}
```

This is the only change needed to make the scope creatable — `api_keys.py`'s existing create/update validation (`requested - VALID_SCOPES`) already rejects unknown scopes, so nothing else in the key-management UI/API needs to change. A tenant admin creates an MCP-dedicated API key and explicitly opts it into `destructive` scope (alongside `read`/`write`/`scan_execute` as needed) via the existing key-creation form/endpoint — no new UI is required for the foundation, though a Wave-later polish item could surface a checkbox/description for it.

**Enforcement:** every new destructive route declares
```python
dependencies=[Depends(RequireScope("destructive"))]
```
`RequireScope` (`yads/auth/deps.py:205-222`) already does exactly this — checks `required_scope in api_key.scopes` and 403s otherwise. It is currently unused by any real route (`v1.py` only uses bare `get_api_key`); Wave 1 will be its first real caller. No changes needed to `RequireScope` itself.

**Which Wave 1 operations are destructive:** purge queue, cancel/revoke a running task, bulk-delete tags globally, delete a single target's tag set via forceful replace. Read/list/tag-add/scan-trigger operations are not destructive — they require only `read`/`write`/`scan_execute` as appropriate, matching the existing scope semantics elsewhere in the codebase.

### `confirm: bool` convention

On top of the scope (not instead of it), every destructive tool's request body carries a required `confirm: bool` field that must be `true`, enforced server-side with a 400 if `false`/absent:

```python
if not payload.confirm:
    raise HTTPException(status_code=400, detail="Set confirm=true to perform this destructive action")
```

Rationale (per the user's own framing when this was decided): this is not a new concept — `labcontrol_mcp`'s destructive tools already use `confirm: bool = True` as a parameter default that the MCP tool description instructs the LLM to set explicitly. Here it is not a Python default (server-trust boundary should not rely on a client-side default) but a required, explicitly-checked field. This means an LLM calling the tool has to affirmatively state its intent in the call itself, which is useful defense against an LLM acting on injected/ambiguous instructions — the scope alone controls *whether the key is allowed to*, `confirm` controls *whether this specific call means to*.

---

## 3. New router surface

Rather than growing `v1.py` into an unbounded file, Wave 1 introduces topic-scoped router modules, all mounted under the same `/api/v1` prefix so they share one coherent API surface and one auth model:

- `yads/api/routers/v1_queue.py` — queue view/control/cancel/purge/undo-purge
- `yads/api/routers/v1_tags.py` — tag list/add/remove/bulk-assign/delete-global
- (Wave 1's "Scanning Execution" group reuses `v1.py`'s existing `POST /api/v1/dast/scan` pattern plus new bulk-scan endpoints — see §5.3)

Each new router file follows `v1.py`'s existing shape exactly:

```python
from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select
from typing import Annotated
from pydantic import BaseModel
from yads.database import get_session
from yads.auth.deps import get_api_key, RequireScope
from yads.models import APIKey, Target

router = APIRouter(prefix="/api/v1", tags=["API v1 — Queue"])
```

`yads/api/main.py` registers each new router the same way `v1.py`'s is presumably already registered (mirror the existing `app.include_router(v1.router)` call site).

All tenant scoping follows the existing `v1.py` idiom: `api_key.tenant_id` is authoritative, never a client-supplied tenant parameter. Every query filters `Target.tenant_id == api_key.tenant_id`.

---

## 4. Generic "export report by category" pattern

Several later waves (Reports & Export) need a family of near-identical endpoints ("export findings CSV", "export targets CSV", "export compliance PDF", ...). To avoid Wave-N duplicating this five times, the foundation establishes one shape now so later waves just add categories:

```python
class ExportCategory(str, Enum):
    targets = "targets"
    findings = "findings"
    # more added by later waves as needed

@router.get("/export/{category}")
async def export_report(
    category: ExportCategory,
    format: str = "csv",
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(get_api_key)],
):
    ...
```

This is **not** part of Wave 1's implementation (Wave 1 has no Reports & Export tools), but the convention is recorded here so the router-naming and category-enum pattern is settled before Reports & Export becomes its own wave.

---

## 5. Wave 1 tools — concrete signatures

19 tools across three candidate-list groups. Each is listed as: MCP tool name → backing YADS endpoint (new unless marked "existing") → scope required → what it does, sourced from the exact current logic in `queue.py`, `tags.py`, `targets.py`.

### 5.1 Queue & Scan Control (7 tools)

| MCP tool | Endpoint | Scope | Behavior (source of truth) |
|---|---|---|---|
| `queue_status` | `GET /api/v1/queue` (new) | `read` | Mirrors `view_queue`'s data gathering (`queue.py:92-97`) minus HTML rendering: `SystemConfig.QUEUE_ACTIVE`, Redis `celery` list, Celery `active()`/`reserved()`/`scheduled()`, filtered to `api_key.tenant_id` via the same `filter_tasks_by_tenant` helper. Returns JSON. |
| `queue_pause` | `POST /api/v1/queue/control` (new) | `write` | Body `{"action": "pause"}`. Same logic as `control_queue` (`queue.py:332-338`) — **note:** the existing implementation revokes/resets DB-wide, not tenant-scoped. This asymmetry (global pause vs. tenant-scoped purge/cancel) is inherited as-is; flagged as a known inconsistency, not fixed silently in this wave (see §6). |
| `queue_resume` | `POST /api/v1/queue/control` (new) | `write` | Body `{"action": "resume"}`. Same caveat as above. |
| `queue_cancel_task` | `POST /api/v1/queue/tasks/{task_id}/cancel` (new) | `write` | Mirrors `cancel_single_task` (`queue.py:433-439`): locates the task, enforces `task_tenant_id == api_key.tenant_id` (403 otherwise — same check as the existing 403 at `queue.py:529`), revokes/removes, resets target to `idle`. |
| `queue_purge` | `POST /api/v1/queue/purge` (new) | `destructive` + `confirm:true` | Mirrors `purge_queue` (`queue.py:586-591`) — tenant-scoped (unlike pause/resume), returns the `undo_batch` id so the caller can undo. |
| `queue_undo_purge` | `POST /api/v1/queue/undo-purge` (new) | `write` | Body `{"undo_batch": "..."}`. Mirrors `undo_purge_queue` (`queue.py:755-759`) — re-dispatches only `api_key.tenant_id`-matching tasks from the cached batch. |
| `queue_list_rate_limited_modules` | `GET /api/v1/queue` (same endpoint as `queue_status`, additional field) | `read` | Surfaces the rate-limited-module badge data added in the scan-queue-rate-limit-resilience feature (`core/module_status.py`) as part of the queue-status payload, not a separate route. |

**Design note on `queue_pause`/`queue_resume`:** the existing HTML `control_queue` action is *not* tenant-scoped — it pauses/resumes the whole worker fleet regardless of which tenant's key calls it. Exposing this to a "destructive"-unscoped `write` key as a system-wide action is a genuine authorization question the current admin UI already accepts (the HTML route uses `scanner_only`, not an admin check). This design keeps parity with existing behavior rather than inventing new tenant semantics unasked; §6 records it as a candidate follow-up (should `queue_pause`/`queue_resume` actually require `destructive` scope, since it affects every tenant's scans?).

### 5.2 Tagging & Organization (6 tools)

| MCP tool | Endpoint | Scope | Behavior |
|---|---|---|---|
| `tags_list` | `GET /api/v1/tags` (new) | `read` | Mirrors `list_tags` (`tags.py:83-85`) but, unlike the existing unscoped version, filters `get_unique_tags(session, tenant_id=api_key.tenant_id)` — the MCP surface must not leak cross-tenant tag vocabularies the way the existing HTML endpoint currently does. This is a deliberate tightening, not a behavior port — flagged in §6. |
| `tags_add_to_target` | `POST /api/v1/targets/{target_id}/tags` (new) | `write` | Mirrors `add_tag` (`tags.py:184-185`) but adds the tenant check the existing route lacks: 404 if `Target.tenant_id != api_key.tenant_id`. |
| `tags_remove_from_target` | `DELETE /api/v1/targets/{target_id}/tags/{tag}` (new) | `write` | Mirrors `remove_tag` (`tags.py:199-200`), same added tenant check. |
| `tags_bulk_assign` | `POST /api/v1/tags/bulk-assign` (new) | `write` | Mirrors `bulk_assign_tags` (`tags.py:88-93`): JSON body `{target_ids: [int], tags: [str], action: "add"|"remove"|"replace"}`, scoped to `api_key.tenant_id`. |
| `tags_bulk_add_by_ids` | `POST /api/v1/targets/bulk/tag` (new) | `write` | Mirrors `bulk_add_tag` (`tags.py:259-264`) — form-shaped in the original, JSON body here: `{target_ids: [int], tag: str}`, with the tenant check the original lacks added. |
| `tags_delete_globally` | `DELETE /api/v1/tags/{tag_name}` (new) | `destructive` + `confirm:true` | Mirrors `delete_tag_globally` (`tags.py:158-163`) — removes the tag from every target in the tenant; irreversible in bulk, hence `destructive`. |

### 5.3 Scanning Execution (6 tools)

| MCP tool | Endpoint | Scope | Behavior |
|---|---|---|---|
| `scan_trigger` | `POST /api/v1/dast/scan` (**existing**, `v1.py:20-56`) | `scan_execute` (already enforced via `get_api_key`; existing route has no `RequireScope`, Wave 1 adds `dependencies=[Depends(RequireScope("scan_execute"))]` to it — a tightening, see §6) | Existing behavior unchanged: find-or-create target by domain, dispatch `run_all_scans` with a `profile`-derived module list. |
| `scan_trigger_by_target_id` | `POST /api/v1/targets/{target_id}/scan` (new) | `scan_execute` | Mirrors `trigger_scan` (`targets.py:752-753`): tenant-scoped lookup, validates `scan_types` against `REGISTRY.keys() | {"dns_cleanup","full_scan"}`, expands `full_scan`, enforces `get_max_concurrent_scans`/`get_active_scan_count`, dispatches with `scan_priority`. |
| `scan_bulk_preview_count` | `GET /api/v1/targets/bulk-scan/preview-count` (new) | `read` | Mirrors `preview_bulk_scan_count` (`targets.py:280-286`): query params `only_roots`, `online_only`, `scanned_before` → `{"count": N}` via `_build_bulk_criteria_query`. |
| `scan_bulk_by_criteria` | `POST /api/v1/targets/bulk-scan` (new) | `scan_execute` | Mirrors `submit_bulk_scan_by_criteria` (`targets.py:296-300`): JSON body `{scan_types: [str], only_roots: bool, online_only: bool, scanned_before: str|null}`, resolves matching target IDs via `_build_bulk_criteria_query`, queues each via `_queue_single_bulk_target`. **This is exactly the operation the user's still-open "empty the queue and find sedoparking domains" request needs** — see §7. |
| `scan_bulk_selected` | `POST /api/v1/targets/bulk/scan` (new) | `scan_execute` | Mirrors `bulk_scan_targets` (`targets.py:105-111`): JSON body `{target_ids: [int], scan_types: [str]}`, no hard cap (matches existing no-cap rationale), tenant-checked per target via `_queue_single_bulk_target`. |
| `scan_get_findings` | `GET /api/v1/findings` (**existing**, `v1.py:59-79`) | `read` | Unchanged — already tenant-scoped, already API-key-authed. Included in Wave 1's tool list as a read-side complement to the write-side scan tools above, not a new endpoint. |

**On `_build_bulk_criteria_query`'s filterable fields** (`targets.py:185-231`, confirmed against `models.py:123-167`): `tenant_id` and `is_archived` are always applied; `only_roots` derives from `domain` via `tldextract` at request time (no dedicated boolean column); `online_only` and `scanned_before` both derive from `ScanResult` subqueries, not `Target` columns (`Target` has no `is_online` or `last_scanned_at` field). `Target.tags` (JSONB) exists but is **not** currently wired into this query — a tag-based bulk-scan filter (e.g. "scan everything tagged `sedoparking`" or its inverse) is not available through `scan_bulk_by_criteria` as it stands today. This matters directly for §7.

---

## 6. Known inconsistencies inherited, not fixed, by this wave

Recorded explicitly so they're a visible decision, not a silent gap:

1. **`queue_pause`/`queue_resume` are fleet-wide, not tenant-scoped**, while `queue_purge`/`queue_cancel_task` are tenant-scoped. Wave 1 exposes the existing behavior as-is. Follow-up candidate: should pause/resume require `destructive` scope given the blast radius?
2. **`tags_list` and the two per-target tag mutation endpoints tighten tenant scoping** relative to their HTML counterparts (which have no tenant check at all on `add_tag`/`remove_tag`, and no tenant filter on `list_tags`). This is a deliberate improvement for the new API-key surface, not a bug port — but it does mean `yads-mcp`'s behavior will visibly differ from the existing HTML UI's behavior for the same nominal operation. Worth a one-line callout in the `yads-mcp` README.
3. **`scan_trigger` (existing `v1.py` route) gains a `RequireScope("scan_execute")` dependency it didn't have before.** Any existing API key already using this endpoint with only `read`/`write` scope (no `scan_execute`) would start getting 403s. Given `v1.py` is presumably lightly used (it's clearly early/prototype code — inline domain parsing, no `RequireScope` anywhere), this is treated as a acceptable tightening rather than a breaking change requiring a deprecation window, but should be called out to the user before merging in case any existing integration relies on it.

---

## 7. Relationship to the still-open "empty queue + find parked domains" request

Earlier in this session the user asked: *"empty the queue and identify me this sedoparking domains with the way you descriped. lets see, what is left without this tag at the end of this huge list..."* — this was left unresolved (blocked on a native confirm-dialog for the queue purge, then superseded by the MCP pivot).

`scan_bulk_by_criteria` (§5.3) plus `queue_purge` (§5.1) are exactly the two operations that request needs, and once Wave 1 ships as real API endpoints, that request becomes a normal MCP-driven workflow: `queue_purge` (destructive+confirm) → `scan_bulk_by_criteria` with `scan_types: ["catchall_detector"]` (or `full_scan` if other modules are wanted too) → poll `queue_status`/`scan_get_findings` for tags. This is not a reason to delay Wave 1, but it is a reason to prioritize `scan_bulk_by_criteria` and `queue_purge` within Wave 1's own implementation order once the plan is written.

Note the gap from §5.3's last paragraph: `scan_bulk_by_criteria` still has no tag-based filter, so "what is left without this tag" (i.e. "scan everything NOT already tagged sedoparking/etc.") isn't directly expressible yet. Within Wave 1 this is worked around by scanning everything matching the existing criteria (e.g. `online_only`) and relying on `catchall_detector`'s idempotent tagging (already-tagged domains simply get re-tagged with the same value, a no-op). A dedicated `tags_exclude` filter on `_build_bulk_criteria_query` is a reasonable small addition but is out of scope for this foundation spec — flagged as a Wave 1 plan candidate, not required for Wave 1 to be useful.

---

## 8. `yads-mcp` repo skeleton

Mirrors `labcontrol_mcp`'s shape exactly (same SDK, same file split):

```
yads-mcp/
├── pyproject.toml
├── README.md
├── yads_mcp/
│   ├── __init__.py
│   ├── server.py       # MCPServer("yads"), @mcp.tool() defs grouped by comment header per wave
│   └── client.py        # thin httpx.Client factory, YADS_URL + YADS_API_KEY env vars
└── tests/
```

`client.py` — one function, matching `labcontrol_mcp/client.py`'s shape:

```python
import httpx
import os
from contextlib import contextmanager

@contextmanager
def yads_client():
    base_url = os.environ["YADS_URL"]
    api_key = os.environ["YADS_API_KEY"]
    with httpx.Client(base_url=base_url, headers={"X-API-Key": api_key}, timeout=30.0) as client:
        yield client
```

`server.py` — one `@mcp.tool()` per row in §5's tables, grouped under `# --- Queue & Scan Control ---` / `# --- Tagging & Organization ---` / `# --- Scanning Execution ---` comment headers, each a direct `client.get/post/delete(...)` call against the endpoints above. Destructive tools carry `confirm: bool` as an explicit required parameter in the tool signature (not defaulted to `True` — the client must pass it, unlike `labcontrol_mcp`'s `confirm: bool = True` convenience default, since a destructive scope + silent-default-true combination would make it too easy for an LLM to fire the call without deliberately setting confirm).

No async job / polling pattern is needed for Wave 1 (unlike LabControl's Ansible-job model) — YADS's scan dispatch is fire-and-forget via Celery, and `queue_status`/`scan_get_findings` already serve as the poll targets.

---

## 9. Out of scope for this spec

- Waves 2–10 (~60 remaining candidate tools) — each gets its own spec, following this document's conventions.
- The `tags_exclude` bulk-scan-criteria filter noted in §7.
- Any UI change to the API-key creation screen to describe the new `destructive` scope (functionally works without one; a one-line copy addition is a natural Wave 1 implementation-plan task, not a design decision).
- Rate limiting/quota specific to MCP usage beyond the existing per-key 60 req/min limit already enforced in `get_api_key`.
