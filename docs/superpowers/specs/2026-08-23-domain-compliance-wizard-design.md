# Domain Compliance Wizard & Brand-Watch Shadow-Domain Discovery

Status: Draft — approved in chat, pending spec review
Author: Claude (with mrmarco), 2026-08-23

## Context

The user's ITDS team is under DORA pressure to maintain
a complete inventory of the bank's internet-facing domains. Two related but
distinct problems exist:

1. **Known-domain hygiene**: ~6000 domains are already registered as YADS
   `Target` rows. Nobody has run a systematic reachability → webserver
   detection → deep content scan pass across all of them.
2. **Shadow domains**: business departments bypass ITDS and
   register new domains carrying corporate brand names (e.g. containing
   "acmecorp") that are never added as YADS targets and thus never
   monitored. Finding these is the actual DORA compliance gap — it's not
   "do we know about the domains we track," it's "what don't we know about."

The existing YADS codebase already has most of the scanning primitives
needed for problem 1 (staged `run_all_scans` with a `scan_types` subset,
criteria-based bulk-scan endpoint built for 5000+ targets, existing
concurrency caps). Problem 2 has no existing implementation — every current
"lookalike domain" module (`typosquat_scanner`, `brand_intelligence`'s
`DomainVariationGenerator`) generates variants *of a domain you already
have*, not a free-text brand search across the open internet.

Both problems are exposed to the user as a single guided flow so ITDS staff
don't need to know which existing subsystems are being orchestrated
underneath.

## Goals

- A new top-level nav item that is a wizard on first use and a status
  dashboard on every subsequent visit.
- Stage the known 6000 targets through reachability+webserver-detection,
  then deep content scan, without ever running the expensive crawl step
  against targets that don't have a live webserver.
- Stand up a recurring "Brand Watch" for the keyword "acmecorp"
  that periodically searches Certificate Transparency logs and enumerates
  the keyword across a broad TLD list, diffs against known targets, and
  surfaces new candidates for human triage.
- Every new-candidate discovery and every triage decision is written to
  the existing hash-chain audit log (DORA evidence trail), for free.

## Non-goals (v1)

- WHOIS/RDAP reverse search and passive-DNS integration — both require
  paid third-party APIs the organisation doesn't have yet. The `BrandWatch` data
  model and the source-discovery code path are designed to be pluggable so
  a second source can be added later without a schema change (see
  `ShadowDomainCandidate.source` below), but no such integration ships now.
- Subsidiary/sub-brand keywords (VR-Bank, Union Investment, DZ HYP,
  TeamBank, etc.) — explicitly out of scope per user decision; only the
  main "acmecorp" keyword is watched in v1.
- Any new scanning logic. Steps 1–3 of the wizard are orchestration over
  existing `run_all_scans` / bulk-scan machinery; no scanner module
  behavior changes.

## User-facing flow

One continuous wizard, 4 steps, reached from a new nav item (placeholder
name: "Domain Compliance"):

1. **Select targets** — criteria picker (all / root-domains-only /
   online-only), reusing the existing `/targets/bulk-scan` criteria
   selection UI/logic against the ~6000 known targets.
2. **Reachability + webserver detection** — fires
   `scan_types=["web_analyzer"]` (reachability is already inline/free in
   `run_all_scans`) across the step-1 selection. Single progress bar
   showing reachable count and webserver-confirmed count.
3. **Deep content scan** — fires `scan_types=["crawler"]`, scoped only to
   the webserver-confirmed subset from step 2. Never runs against the full
   6000.
4. **Brand Watch setup** — enter/confirm the keyword ("acmecorp"), submit.
   Creates a `BrandWatch` row; does not run anything synchronously — the
   first scan happens on the next beat tick (see below).

**Re-entry behavior**: the same nav item loads the tenant's latest
`ComplianceScanRun`. If one exists, the page renders as a status
dashboard — per-step counts, any active `BrandWatch` entries, and a feed of
new `ShadowDomainCandidate` rows needing triage — instead of restarting the
wizard. A "start a new run" action is available once the existing run's
step 3 has finished, for re-scanning later (e.g. quarterly).

## Data model

Two new SQLModel tables, both tenant-scoped like every other YADS table.

### `ComplianceScanRun`

Tracks one wizard run end-to-end so the page can resume as a dashboard.

| Field | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `tenant_id` | int FK | |
| `criteria` | str | serialized step-1 selection (all/root-only/online-only) |
| `current_step` | int | 1–4, drives dashboard rendering |
| `targets_total` | int | count matched by criteria |
| `targets_reachable` | int | updated as step 2 progresses |
| `targets_webserver_confirmed` | int | updated as step 2 progresses |
| `targets_crawled` | int | updated as step 3 progresses |
| `started_at` / `step2_completed_at` / `step3_completed_at` | datetime | nullable until reached |
| `created_by_user_id` | int FK | |

Progress fields are updated by polling existing target/task status
(`Target.status`, `ScanResult` presence per module) rather than by new
per-target bookkeeping — `ComplianceScanRun` is a rollup, not a new
per-target state machine.

### `BrandWatch`

| Field | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `tenant_id` | int FK | |
| `keyword` | str | e.g. "acmecorp" — matching is case-insensitive, hyphen-optional |
| `active` | bool | pause/resume without deleting |
| `last_run_at` | datetime | nullable |
| `created_by_user_id` | int FK | |

### `ShadowDomainCandidate`

| Field | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `brand_watch_id` | int FK | |
| `tenant_id` | int FK | denormalized for query convenience |
| `discovered_domain` | str | |
| `source` | str | `ct_log` \| `tld_enum` (extensible for future `whois`/`passive_dns`) |
| `first_seen_at` | datetime | |
| `status` | str | `new` \| `confirmed` \| `dismissed` |
| `dismissed_reason` | str, nullable | free text, shown so a future re-appearance can be judged against the original reasoning |
| `resolved_target_id` | int FK, nullable | set when `confirmed` promotes this to a real `Target` |

`(brand_watch_id, discovered_domain)` is unique — re-discovering an
already-dismissed domain updates `first_seen_at`'s "last seen" companion
field (not modeled above for brevity, add `last_seen_at`) rather than
creating a duplicate row or resurfacing it in the triage queue.

## Backend orchestration

**Steps 1–3** are wizard-side polling/sequencing logic in the API layer,
not new Celery tasks:
- Step 1 submit → create `ComplianceScanRun`, resolve the criteria to a
  target ID list the same way `/targets/bulk-scan` already does.
- Step 2 submit → dispatch `run_all_scans(..., scan_types=["web_analyzer"])`
  for each target ID (respecting the existing 50-active-per-tenant cap and
  `GLOBAL_MAX_CONCURRENT_SCANS`), advance `current_step` to 2. The
  dashboard view recomputes `targets_reachable`/`targets_webserver_confirmed`
  from `Target`/`ScanResult` state on each load (or via a lightweight
  polling endpoint) rather than the workers pushing updates.
- Step 3 submit → query targets from this run where `web_analyzer` found a
  live server, dispatch `run_all_scans(..., scan_types=["crawler"])` for
  that subset only.

**Step 4 / recurring watch** is a genuinely new periodic task, following
the existing `worker_core.py` `beat_schedule` pattern (one global entry
that iterates all active rows, matching how e.g. `stuck-job-cleaner`
already works — not one dynamically-registered beat entry per tenant):

```python
'brand-watch-scan': {
    'task': 'yads.worker.run_brand_watch_scan',
    'schedule': 24 * 3600.0,  # daily
},
```

`run_brand_watch_scan` iterates every `BrandWatch` where `active=True`:
1. **CT log search**: query `https://crt.sh/?q={keyword}&output=json`
   (substring match, not `%.{domain}`-scoped like the existing
   `ct_monitor.py`) — this is the one code change to the crt.sh query
   shape; reuse `ct_monitor.py`'s cert-parsing helpers where possible, not
   its domain-scoped query construction.
2. **TLD enumeration**: probe the bare keyword across the existing
   ~26-entry TLD list from `tld_scanner.py` (DNS A-record resolution),
   reusing its threaded-probe helper but calling it with the raw keyword
   instead of a known domain's SLD.
3. Diff all discovered domains against the tenant's existing `Target` table
   (case-insensitive) and against already-`dismissed`
   `ShadowDomainCandidate` rows for this `BrandWatch`.
4. Upsert genuinely new domains as `ShadowDomainCandidate(status="new")`.
5. Write an audit log entry summarizing the run (candidates found, sources
   queried) using the existing hash-chain audit log system.

Rate limiting/quota: reuse `brand_intelligence.py`'s `RateLimitedClient`
and `OSINTQuotaManager` patterns for the crt.sh calls, since crt.sh has no
documented hard rate limit but is a shared public resource other tenants'
modules also hit.

**Triage actions** (`ShadowDomainCandidate` status changes) are simple API
endpoints:
- `POST /shadow-domains/{id}/confirm` → create a `Target` from
  `discovered_domain`, set `status="confirmed"`, set `resolved_target_id`,
  audit log entry.
- `POST /shadow-domains/{id}/dismiss` (body: `reason`) → set
  `status="dismissed"`, `dismissed_reason`, audit log entry.

## Error handling

- crt.sh unavailable/timeout on a given `run_brand_watch_scan` tick: log
  and skip, `last_run_at` still updates so the dashboard shows the attempt
  happened; don't retry within the same tick (next day's tick tries again).
- TLD enumeration DNS resolution failures for individual TLDs: per-TLD
  try/except (matches `tld_scanner.py`'s existing pattern), one failing
  TLD doesn't abort the rest.
- Wizard step 2/3 dispatch respecting the existing 50-active-per-tenant
  cap means large criteria selections queue in waves automatically — the
  dashboard should show "queued" vs "running" vs "done" rather than
  assuming everything dispatches immediately.

## Testing

- Unit tests for the crt.sh substring-query parsing and the diff-against-
  known-targets logic (the two genuinely new pieces of logic).
- Unit tests for `ComplianceScanRun` progress rollup computation.
- Manual verification of the full wizard flow against a small target
  subset (not the full 6000) before enabling for real use, given the
  minimal existing test coverage in this codebase generally.

## Open questions for implementation plan

- Exact nav item label/icon and URL path — placeholder "Domain Compliance"
  used throughout this doc.
- Whether `ComplianceScanRun` dashboard polling is plain page-refresh,
  HTMX polling (matches existing patterns per CLAUDE.md), or reuses
  `redis_logger.py`'s live-update mechanism.
- Which role(s) can create a `BrandWatch` / triage candidates — likely
  `tenant_admin`/`scanner`, mirroring existing RBAC, but not yet confirmed.
