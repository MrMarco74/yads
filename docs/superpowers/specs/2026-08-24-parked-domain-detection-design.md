# Parked-Domain Detection: Auto-Skip, Tagging, Scoring, Export

Date: 2026-08-24

## Problem

Domains that resolve to a registrar parking page (Sedo, GoDaddy "this domain
is parked", Bodis, ParkingCrew, Afternic, Dan.com, HugeDomains, generic
"for sale" phrasing) or a default hosting-provider splash page (Apache/nginx/
IIS default page, IONOS/Strato/Hetzner defaults) waste most of a scan's
budget: `crawler`, `visual_osint`, `content_discovery`, `nuclei_scanner`,
`tech_stack_analyzer`, `form_discovery`, `api_discovery`, `graphql_scanner`,
`websocket_scanner`, `login_scanner`, and `password_spray_mapper` all exist
to analyze a real web application or crawl real content, neither of which
a parking page has. Today nothing distinguishes a parked domain from a live
one before dispatch — every selected module runs regardless.

Detection logic for this already exists: `modules/catchall_detector.py`
(`CatchallDetectorScanner`) does 3-layer detection (signature match →
vhost/wildcard comparison → optional LLM fallback) and already produces
`is_catch_all` (`True`/`False`/`None`) plus `matched_signature` (which
provider/pattern matched). It is currently a fully opt-in, simple-dispatch
module (`default_on=False`) with no effect on any other module's execution,
no tagging, no scoring impact, and no export visibility.

## Goals

- Skip the content/app-analysis modules listed above, in the same scan run,
  when a domain is confirmed parked — without touching modules that remain
  meaningful for a parked domain you still own (DNS, SSL/cert, subdomain
  takeover, threat intel, breach/leak monitoring, security headers, etc.).
- Tag the target with a provider-specific label (e.g. `sedoparking`,
  `godaddy-parked`) using the tag system that already exists on `Target`,
  so parked domains are filterable in the existing target-list UI without
  any new tagging infrastructure.
- Reflect a confirmed parked domain as a negative signal in the security
  score.
- Surface the tag in the existing target-list report export.

Explicitly out of scope: a new relational tags table (the existing
`Target.tags` JSONB column plus its CRUD/UI/search already does everything
needed here — see Design §2); a new export endpoint (§5 extends the
existing one instead); filtering the export by tag/selection (today's
`/reports/targets/{csv,excel,pdf}` export unconditionally dumps every
target in the caller's tenant scope — adding a filter parameter to that is
a separate, unrelated piece of work not requested here).

## Design

### 1. Detection & dispatch — `catchall_detector` becomes an early, unconditional check

`catchall_detector`'s registry entry (`core/module_registry.py:279-290`)
changes from a simple-dispatch, opt-in module to `custom_dispatch=True`,
matching the shape of `web_analyzer`/`subdomain_scanner` (both already
`custom_dispatch=True`, each with a hardcoded block in `run_all_scans`):

```python
("catchall_detector", ModuleDef(
    name="catchall_detector",
    label="Catch-All Page Detector",
    label_de="Catch-All-Seiten-Erkennung",
    category="web",
    module_path="yads.modules.catchall_detector:CatchallDetectorScanner",
    worker_note="Checking for parked/catch-all landing page...",
    requires_http=True,
    default_on=False,      # stays opt-in for UI display purposes (§ below)
    finding_module=True,   # now feeds Unified Findings + scoring (§4)
    passive=True,
    custom_dispatch=True,
)),
```

`custom_dispatch=True` removes it from `get_simple_dispatch_modules()`
(so it's no longer part of the chord built in `_dispatch_module_chord`);
the worker gains a new hardcoded block, placed directly after the existing
`has_http`/`has_https` pre-check (`worker_tasks.py:1173-1184`) and before
the `# 1. Subdomain Scanner` block:

```python
# Catch-all / parked-domain pre-check — always runs (not gated on
# scan_types) so its skip decision below is reliable regardless of what
# the tenant selected; still shown as a selectable module in the UI/scan
# profiles so its persisted result is discoverable like any other module.
is_parked = False
if has_http or has_https:
    logger.info(f"[Worker] Checking for parked/catch-all page on {domain}...")
    catchall_scanner = CatchallDetectorScanner(db_session=session)
    with LogCapture() as logs:
        catchall_result = catchall_scanner.process(target_id, domain)
        captured_logs = logs.get_logs()
    if catchall_result and hasattr(catchall_result, 'log_content'):
        catchall_result.log_content = sanitize_null_bytes(captured_logs)
        session.add(catchall_result)
        session.commit()
    # process() only returns a ScanResult when the hash changed; re-derive
    # the live verdict directly so an unchanged (still-parked) result still
    # gates this run.
    live_data = catchall_scanner.run_scan(domain, target_id=target_id)
    is_parked = live_data.get("is_catch_all") is True
    if is_parked:
        logger.info(f"[Worker] {domain} detected as parked ({live_data.get('matched_signature')}) — skipping content/app-analysis modules")
        _tag_parked_domain(session, target_id, live_data.get("matched_signature"))
```

This intentionally calls `run_scan()` a second time after `process()` —
`process()`'s hash/diff/save path doesn't return the raw dict when nothing
changed (the common case on repeat scans of an already-parked domain), and
the gate below needs the live verdict every run, not just on change. Both
calls hit the same already-fetched-once-per-process()-call network path;
`run_scan()` itself does one HTTP GET, so this is two fetches per scan for
parked/borderline domains — acceptable given `catchall_detector` is a
single lightweight request, not a heavy module.

`is_parked` (plus the existing `has_http`, `has_https`) then threads
through to both dispatch mechanisms:

**`_dispatch_module_chord`** (`worker_tasks.py:964-989`) gains a fourth
parameter, `is_parked`, and a new skip list checked alongside the existing
`requires_https`/`requires_http` checks:

```python
PARKED_SKIP_MODULES = {
    "tech_stack_analyzer", "form_discovery", "api_discovery",
    "graphql_scanner", "websocket_scanner", "login_scanner",
    "password_spray_mapper",
}

def _dispatch_module_chord(target_id, domain, tenant_id, scan_types, has_http, has_https, is_parked, scan_start_time):
    module_names = []
    for _mod_def in get_simple_dispatch_modules():
        if _mod_def.name not in scan_types:
            continue
        if _mod_def.requires_https and not has_https:
            logger.info(f"[Worker] Skipping {_mod_def.name}: no HTTPS")
            continue
        if _mod_def.requires_http and not (has_http or has_https):
            logger.info(f"[Worker] Skipping {_mod_def.name}: no HTTP")
            continue
        if is_parked and _mod_def.name in PARKED_SKIP_MODULES:
            logger.info(f"[Worker] Skipping {_mod_def.name}: domain is parked")
            continue
        module_names.append(_mod_def.name)
    ...
```

The call site (`worker_tasks.py:1672-1673`) passes the new `is_parked`
local through positionally, same as `has_http`/`has_https` today.

The four `custom_dispatch=True` modules with their own hardcoded gates —
`crawler`, `visual_osint`, `content_discovery`, `nuclei_scanner` — each
get `and not is_parked` added to their existing `if ... in scan_types`
condition (e.g. the `content_discovery` gate at `worker_tasks.py:~1569`
becomes `if "content_discovery" in scan_types and (has_http or has_https)
and not is_parked:`).

An uncertain verdict (`is_catch_all is None`, e.g. the target didn't
resolve or timed out) is **not** treated as parked — `is_parked` stays
`False` unless the check explicitly returns `True`. This matches the
existing fail-open posture used throughout this codebase's other checks.

### 2. Tagging — reuse `Target.tags`, no new table

`Target.tags` (`models.py:141`, `List[str]` over a `JSONB` column) already
has full CRUD (`api/routers/tags.py`), a filter dropdown and per-row badges
in the target list, bulk-tag actions, and search integration. This design
reuses it as-is — no new table, migration, or UI.

The read-modify-write-commit pattern already used by `add_tag`
(`api/routers/tags.py:184-196`) is duplicated as a small worker-local
helper (Celery tasks don't have a FastAPI `Depends`-injected session, and
routers shouldn't be imported into worker code — this is a 6-line copy,
not a shared import):

```python
def _tag_parked_domain(session: Session, target_id: int, matched_signature: str | None):
    tag = PARKED_TAG_MAP.get(matched_signature, "parked")
    target = session.get(Target, target_id)
    if target and tag not in target.tags:
        new_tags = list(target.tags)
        new_tags.append(tag)
        target.tags = new_tags
        session.add(target)
        session.commit()
```

`PARKED_TAG_MAP` translates `catchall_detector`'s internal signature ids
(`modules/catchall_detector.py:39-68`, the `PARKING_SIGNATURES` list) into
the filter-friendly tag names actually wanted, so tags stay readable even
though signature ids are grouped more granularly (e.g. both `"sedo"`
entries — the domain match and the "this domain is for sale" phrase match —
already collapse to one signature id and thus one tag):

```python
PARKED_TAG_MAP = {
    "sedo": "sedoparking",
    "godaddy_parked": "godaddy-parked",
    "bodis": "bodis-parked",
    "parkingcrew": "parkingcrew-parked",
    "afternic": "afternic-parked",
    "dan_com": "dan-parked",
    "hugedomains": "hugedomains-parked",
    "generic_for_sale": "parked-for-sale",
    # Default hosting/server splash pages are catch-all, not commercially
    # "parked" — tagged generically rather than inventing a per-vendor tag
    # for e.g. every Apache/nginx/IIS default page.
    "apache_ubuntu_default": "placeholder-page",
    "apache_default": "placeholder-page",
    "nginx_default": "placeholder-page",
    "iis_default": "placeholder-page",
    "cpanel_default": "placeholder-page",
    "plesk_default": "placeholder-page",
    "generic_placeholder": "placeholder-page",
    "ionos_default": "placeholder-page",
    "strato_default": "placeholder-page",
    "hetzner_default": "placeholder-page",
}
```

A signature id with no explicit mapping (vhost/LLM-detected matches, whose
`matched_signature` is `None` or a non-signature value) falls back to the
generic `"parked"` tag via `PARKED_TAG_MAP.get(matched_signature, "parked")`.

### 3. Scoring — plug into the existing generic-penalty mechanism

`core/scoring.py` has no flat/override-penalty precedent — every deduction
reads a module's `ScanResult.data`. The existing generic plug-in point,
`_generic_penalize` (`scoring.py:170-184`), already does exactly the shape
needed: a module name maps to `(max_penalty, label)`, and the module is
expected to populate `data["findings"]` with `severity` values the loop
filters on (`"critical"`/`"high"`).

`catchall_detector.run_scan()` gains one addition to its returned dict
when `is_catch_all=True`: a `findings` list with a single high-severity
entry:

```python
result["findings"] = [{
    "severity": "high",
    "title": f"Domain appears to be parked ({live_data.get('matched_signature') or 'unclassified'})",
}]
```

(`findings: []` when not parked, so `crit_high` in the scorer's loop is
empty and no deduction applies — matching how every other module in
`_generic_penalize` behaves when it has nothing to report.)

`scoring.py`'s dict gains one entry:

```python
_generic_penalize = {
    "subdomain_takeover": (15, "Subdomain Takeover Risk"),
    "waf_detector": (0, ""),
    "graphql_scanner": (8, "GraphQL Security Issues"),
    "websocket_scanner": (8, "WebSocket Security Issues"),
    "password_spray_mapper": (5, "Password Spray Surface Exposed"),
    "catchall_detector": (20, "Domain Is Parked / Not In Active Use"),
}
```

A single parked-domain finding deducts `min(20, 1 * 4) = 4` points under
the existing `score -= min(max_pen, len(crit_high) * 4)` formula (one
finding, not a per-severity-count scale like breach counts get) — the
`20` cap exists for consistency with the dict's shape but in practice this
module only ever emits zero or one finding, so the realized deduction is
always exactly 4 points when parked, 0 otherwise. If a heavier penalty is
wanted, the fix is changing the finding-generation side (e.g. emitting
multiple findings) rather than the cap, since the cap only bounds an
already-low per-finding total here.

`catchall_detector` is not currently in `SCORED_MODULE_NAMES`
(`scoring.py:11-16`) or in `latest_results` construction wherever that
dict is built for `calculate_target_score`'s caller — it needs adding to
whatever module-name list feeds `latest_results` so the scorer actually
sees a `catchall_detector` entry to look up.

### 4. Export — extend the existing target-list export, not a new endpoint

`reports.py`'s three target-list export routes
(`/reports/targets/{csv,excel,pdf}`) all source from `_get_targets_data()`
(`reports.py:27-52`) except the CSV route, which duplicates the same
column set inline (`reports.py:93-123`) rather than calling
`_get_targets_data(..., for_export=True)`. Both paths get a `Tags` column
added, sourced from `t.tags` (already loaded on every `Target` row this
function already fetches — no extra query):

- `_get_targets_data()`'s export-dict branch: add `"Tags": ", ".join(t.tags)` to the dict literal (feeds Excel/PDF).
- `export_targets_csv`'s header (`writer.writerow(['ID', 'Domain', 'Created At', 'Last Scan', 'Status'])`) and row-building (`writer.writerow([t.id, t.domain, ...])`) both gain the same `", ".join(t.tags)` value, in the same column position as the dict version for consistency.

No filter parameter is added to these routes — they continue to export
every target in the caller's tenant scope, matching current behavior. A
caller wanting only parked domains uses the existing target-list
`filter_tag` dropdown to find them, then reads the `Tags` column in the
full export, or (already-existing, unrelated to this design) the per-target
PDF/Excel report under `exports.py` for a single target's detail.

## Testing

- Unit test for `PARKED_TAG_MAP`/`_tag_parked_domain`: given each known
  `matched_signature`, the correct tag is appended; an already-tagged
  target isn't duplicated; an unmapped/`None` signature falls back to
  `"parked"`.
- Unit test for `_dispatch_module_chord`: `is_parked=True` excludes every
  name in `PARKED_SKIP_MODULES` from the built chord even when they're in
  `scan_types`; `is_parked=False` leaves them in; a module not in
  `PARKED_SKIP_MODULES` (e.g. `dependency_confusion`) is unaffected by
  `is_parked` either way.
- Unit test for each of the four custom-dispatch gates
  (`crawler`/`visual_osint`/`content_discovery`/`nuclei_scanner`): confirm
  `is_parked=True` skips them regardless of `scan_types`/`has_http`.
- Unit test for the scoring addition: a `catchall_detector` result with one
  high-severity parked finding deducts exactly 4 points and adds the
  expected `factors` label; an empty-findings result deducts nothing.
- Integration-style test (mirroring the queue-widget/finalize_scan tests
  from the prior branch): a full `run_all_scans` dry run against a
  `responses`-mocked parked page confirms the skip list is actually
  excluded from the dispatched chord and the tag/scoring side effects both
  land.
- Manual: trigger a scan against a known-parked test domain (or a
  `responses`-mocked one), confirm the tag appears in the target list
  filter dropdown, the score reflects the deduction, and the `Tags` column
  appears correctly in a CSV/Excel/PDF export of the target list.
