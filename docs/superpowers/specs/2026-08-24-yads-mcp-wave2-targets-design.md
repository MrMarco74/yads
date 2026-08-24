# yads-mcp Wave 2: Target / Asset Management — Design

**Status:** Approved
**Scope:** 12 tools covering target listing, detail, add, delete (single + bulk + undo), archive (bulk + dead-sweep + restore), blocklist, change history, scan status, network context.
**Depends on:** Wave 1 foundation (`docs/superpowers/specs/2026-08-24-yads-mcp-foundation-design.md`) — new work reuses `get_api_key`, `RequireScope`, `require_tenant_scoped_key` from `yads/auth/deps.py`, and the router/tool conventions established by `v1_queue.py`/`v1_tags.py`/`v1_scan.py` and `yads_mcp/server.py` unchanged.

This document is deliberately short: the architectural decisions (auth model, scope taxonomy, destructive+confirm convention, MCP repo shape) are already made and battle-tested by Wave 1. This spec only covers what's specific to the Target/Asset Management domain.

---

## 1. Scope trim from the original candidate list

The original ~80-item survey listed 14 candidates for this group. Three are excluded here:

- **Bulk import (file upload)** and **logo/brand-hunt upload** — no clean MCP fit without adding file-transport machinery; stay UI-only.
- **Global target/finding/tag search** — `list_targets`'s filters (below) plus the existing `tags_list` tool from Wave 1 cover the realistic cases; a fuzzy cross-entity search tool is deferred until a concrete need shows up.
- **"Bulk send targets to Discovery"** — the existing endpoint (`targets.py:544-566`) does nothing server-side; it just redirects the browser to `/discovery?prefill_seeds=...` for a human to review in a wizard. There's no real action to wrap headlessly without first building actual Discovery-session creation, which belongs to a future Discovery-focused wave, not this one.

Also excluded, discovered during research, not part of the original list: `archived.py`'s `POST /bulk-delete-dead` — a pre-existing product bug (raw `session.delete()` with no manual cascade unlike every other delete path in this codebase, and its `archived_reason == "dns_dead"` filter doesn't match what `bulk_archive_dead_targets` actually writes, `"DNS cleanup: empty records"`). Not fixing or exposing it; `bulk_delete_targets` (this wave's own tool, using the same safe cascade pattern as `targets.py`'s `_perform_bulk_delete_from_db`) already covers "permanently delete archived targets" for any caller who wants it.

## 2. New router: `yads/api/routers/v1_targets.py`

Same shape as the three existing `v1_*.py` routers: `APIRouter(prefix="/api/v1", tags=["API v1 — Targets"])`, `require_tenant_scoped_key` on every route, `RequireScope` per the table below, tenant-scoped queries throughout (`Target.tenant_id == api_key.tenant_id`, never a client-supplied tenant).

## 3. Tool-by-tool design

### `list_targets` — `GET /api/v1/targets`

Curated filter subset (not the dashboard's 20+ raw filters — those are UI power-filters keyed to specific scanner-module JSONB fields, low value in an agent's hands and would bloat the tool signature past usefulness):

```
tag: str | None            # exact tag match (Target.tags contains)
online: bool | None        # reuses view_target_table's "online" definition (infra/web_analyzer/port_scanner subquery)
scan_status: str | None    # "idle" | "queued" | "running" | "failed"
domain_search: str | None  # substring match on Target.domain (ILIKE %term%)
archived: bool = False     # mirrors filter_archived's "no" default
last_scanned_before: str | None  # ISO date; same "before or never" semantics as scan_bulk_by_criteria's scanned_before (Wave 1 precedent)
page: int = 1
limit: int = 20            # capped at 100, matching get_target_changes's precedent
```

Response: `{"targets": [{"id", "domain", "scan_status", "tags", "is_archived", "created_at"}], "total": N, "page": N}`. Deliberately NOT the full `target_table.html` HTML response — a fresh, lean JSON shape.

### `get_target` — `GET /api/v1/targets/{target_id}`

Lean JSON summary, not `view_target_detail`'s ~40-module HTML dump. Returns: `{"id", "domain", "scan_status", "scan_progress", "tags", "is_archived", "archived_reason", "created_at", "last_scan_at", "module_count"}` — enough for an agent to orient itself and decide whether to call `scan_get_findings` (Wave 1) or `get_target_changes` (this wave) for more.

### `add_target` — `POST /api/v1/targets`

New JSON-body variant (`{"domain": str}`) of the existing HTMX form handler. Preserves existing behavior exactly: SSRF-blocks internal targets (`_is_internal_target`), find-or-create by `(domain, tenant_id)`, no auto-triggered scan (matches the existing handler's own explicit "disabled by user request" comment). Returns the created/existing target's `id`.

### `bulk_delete_targets` — `POST /api/v1/targets/bulk-delete` — **destructive**

`{"target_ids": [int], "confirm": bool}` (no default on `confirm`, per Wave 1's established convention). Mirrors `bulk_delete_targets`'s existing logic exactly: revoke active/queued Celery tasks for those targets, cascade-delete via the same 12-table raw-SQL sequence `_perform_bulk_delete_from_db` uses, snapshot `{domain, tags, discovery_reason}` per target into Redis with a 60s TTL, return `{"deleted_count", "revoked_count", "undo_batch"}`.

**Known limitation, inherited not fixed:** the 60-second undo window is tight for a second MCP round-trip (agent has to notice the mistake, formulate the undo call, and the network/LLM latency all eat into it). This is the same window the existing HTML UI has; not widening it is a deliberate scope decision — a longer window is a `targets.py`-side change orthogonal to exposing it as a tool, and belongs to a future iteration if it proves to be a real problem in practice.

### `undo_bulk_delete_targets` — `POST /api/v1/targets/bulk-delete/undo`

`{"undo_batch": str}`. Mirrors `undo_bulk_delete_targets` exactly: re-creates targets from the Redis snapshot (domain/tags/discovery_reason only — scan history is genuinely gone), skips entries whose tenant doesn't match the caller's key, skips already-existing domains (idempotent against double-calls). Returns `{"restored_count"}`.

### `bulk_archive_targets` — `POST /api/v1/targets/bulk-archive`

`{"target_ids": [int]}`. Not destructive — archiving is reversible via `restore_target`. Sets `is_archived=True`, `archived_reason="manual"`. Returns `{"archived_count"}`.

### `archive_dead_targets` — `POST /api/v1/targets/archive-dead`

No body. Tenant-wide sweep matching `bulk_archive_dead_targets`'s exact subquery (`dns_scanner`'s most recent result has empty `records`), sets `archived_reason="DNS cleanup: empty records"`. Not destructive (reversible via restore). Returns `{"archived_count"}`.

### `restore_target` — `POST /api/v1/targets/{target_id}/restore`

No body. Mirrors `archived.py`'s `restore_target`: clears `is_archived`/`archived_at`/`archived_reason`. Returns the target's current state.

### `bulk_blocklist_targets` — `POST /api/v1/targets/bulk-blocklist` — **destructive**

`{"target_ids": [int], "confirm": bool}`. Mirrors the existing coupling exactly (archiving is bundled with blocklisting in the current UI action, and this wave keeps that coupling rather than introducing a new decoupled semantic the rest of the product doesn't have): inserts an exact-match `DiscoveryDomainBlocklist.pattern` row per target (skipping ones already present) AND archives each target with `archived_reason="blocklisted"`. Classified destructive because — unlike plain archiving — there's no single-action undo: reversing it requires both `restore_target` AND a separate blocklist-row deletion, and no blocklist-management tool exists in this wave (blocklist CRUD wasn't in the original candidate survey under this group; if it's wanted, it's a small follow-up, not blocking this wave). Returns `{"blocklisted_count", "archived_count"}`.

### `get_target_changes` — `GET /api/v1/targets/{target_id}/changes`

`limit: int = 30` (capped at 100, matching the existing endpoint's own cap). Already a clean, tenant-scoped JSON endpoint (`targets.py:1992-2021`) — the new tool is close to a direct passthrough, just re-homed under `/api/v1` with `get_api_key`/`RequireScope("read")` instead of `get_current_active_user`.

### `get_scan_status` — `GET /api/v1/targets/{target_id}/scan-status`

**Fixes a real gap found during research:** the existing `GET /api/scans/{target_id}/status` (`targets.py:985-1003`) has no auth dependency and no tenant check at all — any caller can query any target's scan status by guessing an ID. The new `/api/v1` version adds `require_tenant_scoped_key` and a tenant-scoped lookup (404 if the target isn't the caller's), closing this gap the same way Wave 1's final review closed the NULL-tenant fail-open gap. Behavior otherwise unchanged: live status from Redis if present, else DB fallback (`scan_progress` or `scan_status`).

### `get_network_context` — `GET /api/v1/targets/{target_id}/network-context`

Already tenant-checked in the existing endpoint (`targets.py:1037-1053`) — straightforward mirror under `/api/v1` with `require_tenant_scoped_key` replacing the existing manual `if user.role != "admin" and target.tenant_id != user.tenant_id` check (same effect, reuses the shared dependency instead of duplicating the check inline).

## 4. Scope summary

| Scope | Tools |
|---|---|
| `read` | `list_targets`, `get_target`, `get_target_changes`, `get_scan_status`, `get_network_context` |
| `write` | `add_target`, `undo_bulk_delete_targets`, `bulk_archive_targets`, `archive_dead_targets`, `restore_target` |
| `destructive` (+ `confirm`) | `bulk_delete_targets`, `bulk_blocklist_targets` |

## 5. MCP tool group

`yads_mcp/server.py` gets a fourth group, `# --- Target & Asset Management ---`, 12 tools, same one-`with client()`-call-per-tool shape as every existing tool, using the shared `_ok()` error-detail helper (Wave 1's final-review fix) from the start — no retrofitting needed this time.

## 6. Explicitly out of scope for this wave

- Discovery-session creation/management (belongs to a future Discovery-focused wave).
- Blocklist CRUD beyond what `bulk_blocklist_targets` does inline (add-only, coupled to archiving).
- File-based bulk import, logo upload.
- A dedicated cross-entity search tool.
