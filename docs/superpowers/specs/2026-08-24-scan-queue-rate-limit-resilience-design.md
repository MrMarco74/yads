# Scan Queue Rate-Limit Resilience

Date: 2026-08-24

## Problem

Many scan modules call external APIs — some public/keyless and shared across
every tenant's scans (crt.sh, api.hackertarget.com, ipinfo.io,
web.archive.org/cdx, stat.ripe.net, checkurl.phishtank.com,
registry.npmjs.org, hstspreload.org, itunes.apple.com), some BYOK
(shodan, censys, hibp, virustotal, otx, abuseipdb). None of these detect
when the provider itself starts blocking or rate-limiting us (HTTP 429/403,
provider-specific "quota exceeded" bodies). `core/api_rate_limiter.py`
already self-throttles our *outgoing* request rate for the BYOK services,
but that's proactive and configured by us — it does nothing when a provider
blocks us anyway (wrong assumed limit, shared-IP contention, plan changes),
and the keyless group has no throttling or detection at all.

Today all of these modules run inside one Celery task per target
(`yads.worker.run_all_scans`), dispatched from a `ThreadPoolExecutor` over
`core.module_registry.get_simple_dispatch_modules()` (worker_tasks.py
~1315-1385). A blocked module currently either silently returns nothing or
throws, is logged, and the scan moves on — there's no detection, no
backoff, and no mechanism to retry later without re-running the entire
target's scan.

## Goals

- Detect provider-side blocking/rate-limiting (not just our own throttling)
  for both the keyless and BYOK module groups.
- When blocked, skip the module for the current scan without failing the
  scan, and mark it visibly "rate limited" rather than silently empty.
- Retry the blocked module later, spread out (jittered) so many
  simultaneously-blocked targets don't re-trip the same provider at once.
- Make module scheduling independent enough that one blocked module no
  longer needs to share a task lifetime with the rest of a target's scan.

Out of scope: the hardcoded `custom_dispatch=True` modules
(`subdomain_scanner`, `dns_cleanup`, `web_analyzer`, `dns_scanner`,
`infrastructure_scanner`, etc. — the ones with bespoke blocks in
`run_all_scans` rather than going through the registry loop) keep their
current sequential/threaded execution. The one exception is detection:
`dns_scanner`'s crt.sh calls (`crtSH_client.py`) still route through the
new circuit-breaker-aware HTTP client, since crt.sh is a shared keyless API
and a platform-wide block there is exactly the failure mode this design
exists to prevent — it just doesn't get the chord/retry restructuring since
its host task isn't moving.

## Architecture

### 1. Circuit breaker — `core/api_circuit_breaker.py` (new)

A Redis-backed sibling to `ApiRateLimiter`, same singleton/fail-open
pattern. Tracks provider-side blocking state per service:

```python
class ApiCircuitBreaker:
    def is_blocked(self, service: str) -> bool: ...
    def record_block(self, service: str, retry_after: Optional[int] = None) -> int:
        """Marks service blocked. Returns the cooldown applied, in seconds."""
    def clear(self, service: str) -> None: ...  # successful call after being blocked
```

Redis key: `circuit:blocked:{service}` → cooldown-until timestamp, with a
TTL equal to the cooldown.

Backoff: if `retry_after` is given (from a `Retry-After` header), use it
directly. Otherwise start at 5 minutes; each `record_block()` call that
lands while the service is *already* blocked doubles the next cooldown
(read the previous cooldown from a second key `circuit:cooldown:{service}`,
stored uncapped-by-TTL so it persists across blocks), capped at 6 hours.
A `clear()` call (on a subsequent successful response) resets the cooldown
back to the 5-minute floor.

On Redis error: fail-open (`is_blocked` returns False), matching
`ApiRateLimiter`'s existing philosophy — availability of scanning beats
perfect throttling.

### 2. Detection — extend `core/throttled_http.py`

`ThrottledSession` gains a `service` concept (currently it only tracks
`domain`). Modules pass a logical service name (`"crt_sh"`,
`"hackertarget"`, `"ipinfo"`, `"shodan"`, ... — same naming convention
`ApiRateLimiter.LIMITS` already uses) alongside the URL.

```python
def request(self, method, url, service: str = None, **kwargs):
    ...
    if service and circuit_breaker.is_blocked(service):
        raise ApiBlockedError(service)
    response = super().request(...)
    if service:
        _classify_response(service, response)  # may raise ApiBlockedError
    return response
```

`_classify_response`: 429 or 403 → blocked (read `Retry-After` if present).
Otherwise check a small per-service signature table for known non-standard
throttle bodies (hackertarget's `"error check your search parameter"` /
`"API count exceeded"`, RIPEstat's rate-limit message, etc.) — only the
services known to not use proper status codes need an entry; default is
status-code-only. A match calls `circuit_breaker.record_block(service,
retry_after)` and raises `ApiBlockedError(service, retry_after)`. A
non-blocked 2xx after a prior block calls `circuit_breaker.clear(service)`.

`ApiBlockedError(Exception)` carries `.service` and `.retry_after` so
callers can react without string-matching.

Every module in both groups (keyless + BYOK) switches its raw
`requests`/`self.http` calls for that external API to
`throttled_get(url, service="...")` (or the session equivalent). BYOK
modules keep their existing `ApiRateLimiter.acquire()` self-throttle call
before this — the two are complementary, not a replacement for each other.

### 3. Queue restructuring — worker_tasks.py

Replace the `ThreadPoolExecutor` loop over `get_simple_dispatch_modules()`
with a Celery **chord**: one task per module, one callback that resumes the
finalize work that currently follows the parallel block.

```python
@celery_app.task(name="yads.worker.run_scan_module", queue="discovery",
                  acks_late=True, reject_on_worker_lost=True)
def run_scan_module(target_id, domain, module_name, tenant_id, attempt=0):
    ...
    try:
        result = mod_instance.process(target_id, domain)
        # persist result as today
    except ApiBlockedError as e:
        _mark_rate_limited(target_id, module_name)
        if attempt < MAX_BLOCKED_RETRIES:  # 5
            cooldown = e.retry_after or DEFAULT_COOLDOWN
            jitter = random.uniform(0.5, 1.5)
            run_scan_module.apply_async(
                args=[target_id, domain, module_name, tenant_id],
                kwargs={"attempt": attempt + 1},
                countdown=cooldown * jitter,
            )
        # returns normally either way — does NOT fail, and does NOT hold
        # up the chord: the follow-up (if any) is a separate, independent
        # task, not a retry of this one.
```

`run_all_scans` becomes:

```python
module_tasks = [
    run_scan_module.s(target_id, domain, m.name, tenant_id)
    for m in get_simple_dispatch_modules() if m.name in scan_types
    and _passes_http_precheck(m, has_http, has_https)
]
if module_tasks:
    chord(module_tasks)(finalize_scan.s(target_id, domain, tenant_id, scan_types, scan_start_time))
else:
    finalize_scan(target_id, domain, tenant_id, scan_types, scan_start_time)
```

`finalize_scan` is the existing tail of `run_all_scans` extracted verbatim:
subdomain auto-queue, compliance recalculation, status reset to `idle`,
webhooks, Splunk/Prometheus events, email notification. It does **not**
wait for jittered retry follow-ups — those are deliberately outside the
chord (see below for why) and update their own `ScanResult` row
independently whenever they eventually run; the next full scheduled scan
picks up any resulting compliance-score drift normally.

**Why retries live outside the chord:** a chord callback fires only once
every grouped task has returned. If a blocked module's retry used
`self.retry(countdown=...)` it would keep the chord open — with cooldowns
that can reach 6 hours, that would block `finalize_scan` (and therefore the
target's status reset and `scan_finished` webhook) for hours. Instead the
module task always returns promptly (blocked or not), letting the chord
close on schedule, and a blocked module's eventual success is a fire-and-
forget side effect handled the same way a manually re-run single module
would be.

### 4. Status surfacing

`_mark_rate_limited(target_id, module_name)` sets
`yads:module_status:{target_id}:{module_name} = "rate_limited"` in Redis
with a TTL matching the circuit's cooldown. The queue view and target
detail view read this (same place that already renders the
`get_degraded_modules()` "limited mode" badge) to show a "rate limited —
retrying" badge instead of leaving the module looking silently empty. The
key expires naturally once the cooldown passes or the retry succeeds (which
also clears it explicitly).

## Module migration list

**Keyless, added to `ApiRateLimiter.LIMITS` (conservative default) + routed
through the new client:**
`crt_sh` (crtSH_client.py, ct_monitor.py, dns_scanner.py's CT fallback),
`hackertarget` (dns_history_scanner.py, dns_scanner.py fallback),
`ipinfo` (asn_scanner.py, infrastructure_scanner.py, ipv6_scanner.py),
`wayback` (wayback_scanner.py), `ripestat` (rpki_scanner.py), `phishtank`
(phishing_scanner.py), `npm_registry` (dependency_confusion.py),
`hstspreload` (tls_deep_scanner.py), `itunes` (mobile_app_discovery.py).

**BYOK, keep existing `ApiRateLimiter` self-throttle, add circuit-breaker
detection on top:** `shodan`, `censys` (shodan_censys_scanner.py),
`virustotal`, `otx`, `abuseipdb` (threat_intel_scanner.py), `hibp`
(leak_monitor.py, email_intelligence.py).

## Testing

- Unit tests for `ApiCircuitBreaker` (block/backoff-doubling/clear/TTL,
  Redis-error fail-open) mirroring the existing `ApiRateLimiter` tests.
- Unit tests for `_classify_response` against real captured 429/403 bodies
  and each signature-table entry.
- Integration test: `run_scan_module` on a module whose client raises
  `ApiBlockedError` — assert it marks rate-limited, returns without
  raising, and schedules exactly one follow-up `apply_async` with
  `attempt=1`.
- Integration test: `run_all_scans` with an empty `module_tasks` list still
  calls `finalize_scan` directly (no chord edge case).
- Manual: trigger a scan against a target with `AUTO_QUEUE_SUBDOMAINS` on,
  confirm chord finalize still fires subdomain auto-queue/compliance/
  webhook exactly once per scan.
