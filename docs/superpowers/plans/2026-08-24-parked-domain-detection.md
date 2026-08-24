# Parked-Domain Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect parked/placeholder domains (Sedo, GoDaddy parking, default hosting splash pages, etc.) early in every scan, skip the content/app-analysis modules that waste time on them, tag the target with the matched provider using the existing tag system, deduct from the security score, and surface the tag in the existing target-list export.

**Architecture:** `catchall_detector` (existing 3-layer parking detector) is promoted from an opt-in, simple-dispatch module to an always-run, `custom_dispatch=True` early check in `run_all_scans` — the same shape as `web_analyzer`/`subdomain_scanner`. Its live verdict threads an `is_parked` flag into both dispatch mechanisms (the chord-building filter and four hardcoded custom-dispatch gates). A tag and a scoring finding are emitted using two existing, unmodified subsystems (`Target.tags`, `scoring.py`'s generic-penalty hook) rather than new infrastructure.

**Tech Stack:** Python 3.12, SQLModel, Celery, pytest.

**Spec:** `docs/superpowers/specs/2026-08-24-parked-domain-detection-design.md`

## Global Constraints

- No new database table, migration, or scoring/tagging subsystem — reuse `Target.tags` (JSONB) and `scoring.py`'s `_generic_penalize` dict exactly as they exist today.
- `is_catch_all is None` (uncertain/unreachable) is never treated as parked — `is_parked` stays `False` unless the check explicitly returns `True`.
- The export routes (`/reports/targets/{csv,excel,pdf}`) keep exporting every target in the caller's tenant scope unconditionally — no filter parameter is added.
- `catchall_detector` stays `default_on=False` in the registry (visible/selectable in the UI) even though the worker now runs it unconditionally every scan regardless of `scan_types` — these are independent: the registry flag controls UI checkbox default state, the worker dispatch controls actual execution.

---

## Task 1: Parked-domain tag mapping helper

**Files:**
- Create: `yads/core/parked_domain_tags.py`
- Test: `tests/test_parked_domain_tags.py`

**Interfaces:**
- Produces: `PARKED_TAG_MAP: Dict[str, str]` (signature id → tag string), `tag_parked_domain(session: Session, target_id: int, matched_signature: Optional[str]) -> None` — reads the `Target` row, appends the mapped tag to `target.tags` if not already present, commits. No-op if `target_id` doesn't resolve to a row.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_parked_domain_tags.py
import pytest
from sqlmodel import Session, SQLModel, create_engine
from yads.models import Target
from yads.core.parked_domain_tags import PARKED_TAG_MAP, tag_parked_domain


@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _make_target(session, domain="example.com", tags=None):
    t = Target(domain=domain, tags=tags or [])
    session.add(t)
    session.commit()
    session.refresh(t)
    return t


def test_known_signature_maps_to_expected_tag():
    assert PARKED_TAG_MAP["sedo"] == "sedoparking"
    assert PARKED_TAG_MAP["godaddy_parked"] == "godaddy-parked"
    assert PARKED_TAG_MAP["bodis"] == "bodis-parked"
    assert PARKED_TAG_MAP["generic_for_sale"] == "parked-for-sale"
    assert PARKED_TAG_MAP["apache_default"] == "placeholder-page"
    assert PARKED_TAG_MAP["ionos_default"] == "placeholder-page"


def test_tag_parked_domain_appends_mapped_tag(session):
    target = _make_target(session)
    tag_parked_domain(session, target.id, "sedo")
    session.refresh(target)
    assert target.tags == ["sedoparking"]


def test_tag_parked_domain_does_not_duplicate(session):
    target = _make_target(session, tags=["sedoparking"])
    tag_parked_domain(session, target.id, "sedo")
    session.refresh(target)
    assert target.tags == ["sedoparking"]


def test_tag_parked_domain_preserves_existing_tags(session):
    target = _make_target(session, tags=["customer-a"])
    tag_parked_domain(session, target.id, "godaddy_parked")
    session.refresh(target)
    assert set(target.tags) == {"customer-a", "godaddy-parked"}


def test_tag_parked_domain_unmapped_signature_falls_back_to_generic():
    session_stub = None  # not needed for this assertion
    assert PARKED_TAG_MAP.get("some_unknown_signature", "parked") == "parked"
    assert PARKED_TAG_MAP.get(None, "parked") == "parked"


def test_tag_parked_domain_missing_target_is_noop(session):
    # Should not raise for a target_id that doesn't exist
    tag_parked_domain(session, 999999, "sedo")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_parked_domain_tags.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'yads.core.parked_domain_tags'`

- [ ] **Step 3: Implement `yads/core/parked_domain_tags.py`**

```python
"""
Maps catchall_detector's matched parking/placeholder signature ids to
filter-friendly Target tags, and applies them.

Reuses the existing Target.tags (JSONB) read-modify-write-commit pattern
already used by api/routers/tags.py's add_tag — duplicated here rather
than imported, since this runs from a Celery worker task (no FastAPI
Depends-injected session) and routers shouldn't be imported into worker
code.
"""

from typing import Dict, Optional

from sqlmodel import Session

from yads.models import Target

PARKED_TAG_MAP: Dict[str, str] = {
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
    # for every Apache/nginx/IIS default page.
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


def tag_parked_domain(session: Session, target_id: int, matched_signature: Optional[str]) -> None:
    """Append the tag mapped from matched_signature to the target, if not already present."""
    tag = PARKED_TAG_MAP.get(matched_signature, "parked")
    target = session.get(Target, target_id)
    if target and tag not in target.tags:
        new_tags = list(target.tags)
        new_tags.append(tag)
        target.tags = new_tags
        session.add(target)
        session.commit()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_parked_domain_tags.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add yads/core/parked_domain_tags.py tests/test_parked_domain_tags.py
git commit -m "feat: add parked-domain signature-to-tag mapping and tagging helper"
```

---

## Task 2: `catchall_detector` emits a scoring finding when parked

**Files:**
- Modify: `yads/modules/catchall_detector.py`
- Test: `tests/test_catchall_detector_findings.py`

**Interfaces:**
- Produces: `run_scan()`'s returned dict now always includes a `"findings"` key — a list containing one `{"severity": "high", "title": "..."}` dict when `is_catch_all` is `True`, and an empty list `[]` in every other case (unreachable, no match, explicitly not parked).

- [ ] **Step 1: Read the current file to confirm exact structure**

Read `yads/modules/catchall_detector.py` in full. Confirm these known set-points for `is_catch_all` (from prior investigation — verify against the actual file, which may have shifted slightly):
- Line ~100 (unreachable-target early return): `"is_catch_all": None,`
- Line ~115 (default result dict init, before any match): `"is_catch_all": False,`
- Lines ~128, ~134, ~144, ~154 (four separate match branches — empty-body heuristic, signature match, vhost/wildcard comparison, LLM classification): each sets `result["is_catch_all"] = True` in place.

- [ ] **Step 2: Write the failing tests**

```python
# tests/test_catchall_detector_findings.py
"""
Verifies catchall_detector.run_scan() always includes a "findings" key,
populated with one high-severity entry when is_catch_all is True and
empty otherwise. This is what scoring.py's generic-penalty mechanism
(Task 4) reads.
"""
import pytest
import responses
from yads.modules.catchall_detector import CatchallDetectorScanner


@responses.activate
def test_findings_populated_when_parked_via_signature_match():
    responses.add(
        responses.GET, "http://example.com/",
        body="<html><title>example.com</title>This domain is for sale. Visit sedoparking.com</html>",
        status=200,
    )
    scanner = CatchallDetectorScanner(db_session=None)
    result = scanner.run_scan("example.com", target_id=None)
    assert result["is_catch_all"] is True
    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "high"
    assert "parked" in result["findings"][0]["title"].lower()


@responses.activate
def test_findings_empty_when_not_parked():
    responses.add(
        responses.GET, "http://example.com/",
        body="<html><title>Acme Corp</title>Welcome to our real business site.</html>",
        status=200,
    )
    scanner = CatchallDetectorScanner(db_session=None)
    result = scanner.run_scan("example.com", target_id=None)
    assert result["is_catch_all"] is False
    assert result["findings"] == []


def test_findings_empty_when_unreachable():
    scanner = CatchallDetectorScanner(db_session=None)
    # A domain that will fail to resolve/connect — matches the module's
    # existing unreachable-target handling.
    result = scanner.run_scan("this-domain-does-not-exist-abcxyz123.invalid", target_id=None)
    assert result["is_catch_all"] is None
    assert result["findings"] == []
```

Adjust the mocked URL/scheme (`http://` vs `https://`) and request-matching if the module's actual fetch logic differs from what's assumed here — read the file first (Step 1) to confirm.

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_catchall_detector_findings.py -v`
Expected: FAIL with `KeyError: 'findings'`

- [ ] **Step 4: Modify `yads/modules/catchall_detector.py`**

At each of the two "not parked" set-points (`is_catch_all: None` and `is_catch_all: False`), add `"findings": [],` alongside it in the same dict literal.

At each of the four "is parked" set-points (wherever `result["is_catch_all"] = True` is set in place, across the empty-body heuristic, signature match, vhost/wildcard comparison, and LLM classification branches), add immediately after:

```python
                result["findings"] = [{
                    "severity": "high",
                    "title": f"Domain appears to be parked ({result.get('matched_signature') or 'unclassified'})",
                }]
```

(Match the existing indentation at each specific location — these are four separate branches, not one shared code path.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_catchall_detector_findings.py -v`
Expected: PASS (3 tests)

- [ ] **Step 6: Commit**

```bash
git add yads/modules/catchall_detector.py tests/test_catchall_detector_findings.py
git commit -m "feat: catchall_detector emits a scoring finding when domain is parked"
```

---

## Task 3: Registry entry — `catchall_detector` becomes `custom_dispatch=True`

**Files:**
- Modify: `yads/core/module_registry.py`
- Test: `tests/test_catchall_detector_registry.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `REGISTRY["catchall_detector"]` now has `custom_dispatch=True` and `finding_module=True` (was `False`); `default_on` stays `False`. This removes it from `get_simple_dispatch_modules()`'s output — later tasks (5, 6, 7) depend on this.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_catchall_detector_registry.py
from yads.core.module_registry import REGISTRY, get_simple_dispatch_modules


def test_catchall_detector_is_custom_dispatch():
    defn = REGISTRY["catchall_detector"]
    assert defn.custom_dispatch is True


def test_catchall_detector_is_finding_module():
    defn = REGISTRY["catchall_detector"]
    assert defn.finding_module is True


def test_catchall_detector_stays_opt_in_by_default():
    defn = REGISTRY["catchall_detector"]
    assert defn.default_on is False


def test_catchall_detector_excluded_from_simple_dispatch():
    names = [m.name for m in get_simple_dispatch_modules()]
    assert "catchall_detector" not in names
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_catchall_detector_registry.py -v`
Expected: FAIL — `custom_dispatch` is `False`, `catchall_detector` still appears in `get_simple_dispatch_modules()`

- [ ] **Step 3: Modify `yads/core/module_registry.py`**

Find the `catchall_detector` entry (currently):

```python
    ("catchall_detector", ModuleDef(
        name="catchall_detector",
        label="Catch-All Page Detector",
        label_de="Catch-All-Seiten-Erkennung",
        category="web",
        module_path="yads.modules.catchall_detector:CatchallDetectorScanner",
        worker_note="Checking for parked/catch-all landing page...",
        requires_http=True,
        default_on=False,      # explicit opt-in — extra requests + optional LLM cost
        finding_module=False,  # recon/triage signal, not a vulnerability
        passive=True,
    )),
```

Replace with:

```python
    ("catchall_detector", ModuleDef(
        name="catchall_detector",
        label="Catch-All Page Detector",
        label_de="Catch-All-Seiten-Erkennung",
        category="web",
        module_path="yads.modules.catchall_detector:CatchallDetectorScanner",
        worker_note="Checking for parked/catch-all landing page...",
        requires_http=True,
        default_on=False,     # stays opt-in for UI display — worker runs it
                               # unconditionally regardless (see worker_tasks.py)
        finding_module=True,  # now feeds Unified Findings + scoring
        passive=True,
        custom_dispatch=True,
    )),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_catchall_detector_registry.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add yads/core/module_registry.py tests/test_catchall_detector_registry.py
git commit -m "feat: promote catchall_detector to custom_dispatch, finding_module"
```

---

## Task 4: Scoring — `catchall_detector` deducts via the existing generic-penalty hook

**Files:**
- Modify: `yads/core/scoring.py`
- Test: `tests/test_scoring_catchall_penalty.py`

**Interfaces:**
- Consumes: `catchall_detector`'s `findings` list (Task 2, already merged when this task runs).
- Produces: `SCORED_MODULE_NAMES` includes `"catchall_detector"`; `_generic_penalize` includes `"catchall_detector": (20, "Domain Is Parked / Not In Active Use")`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_scoring_catchall_penalty.py
from types import SimpleNamespace
from yads.core.scoring import calculate_target_score, SCORED_MODULE_NAMES


def _mod_result(data):
    return SimpleNamespace(data=data)


def test_catchall_detector_in_scored_module_names():
    assert "catchall_detector" in SCORED_MODULE_NAMES


def test_parked_domain_deducts_from_score():
    latest_results = {
        "catchall_detector": _mod_result({
            "is_catch_all": True,
            "findings": [{"severity": "high", "title": "Domain appears to be parked (sedo)"}],
        }),
    }
    score, grade, factors = calculate_target_score(target=None, latest_results=latest_results)
    assert score == 96  # 100 - min(20, 1*4)
    assert any("parked" in f.lower() for f in factors)


def test_not_parked_domain_no_deduction():
    latest_results = {
        "catchall_detector": _mod_result({"is_catch_all": False, "findings": []}),
    }
    score, grade, factors = calculate_target_score(target=None, latest_results=latest_results)
    assert score == 100
    assert not any("parked" in f.lower() for f in factors)


def test_missing_catchall_result_no_deduction():
    score, grade, factors = calculate_target_score(target=None, latest_results={})
    assert score == 100
```

If `calculate_target_score`'s `target` parameter is used for something these tests don't exercise (check the actual signature/body when implementing — Task 4 Step 1), pass a minimal stand-in instead of `None`, or adjust the tests to match whatever the function actually needs; the deduction assertions are what matters here, not the exact call shape.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_scoring_catchall_penalty.py -v`
Expected: FAIL — `"catchall_detector" in SCORED_MODULE_NAMES` is False; scores are 100 in both parked cases

- [ ] **Step 3: Modify `yads/core/scoring.py`**

Add `"catchall_detector"` to `SCORED_MODULE_NAMES` (lines 11-16).

In `_generic_penalize` (lines 170-176), add one entry:

```python
    _generic_penalize = {
        "subdomain_takeover": (15, "Subdomain Takeover Risk"),
        "waf_detector": (0, ""),  # WAF is good, no penalty
        "graphql_scanner": (8, "GraphQL Security Issues"),
        "websocket_scanner": (8, "WebSocket Security Issues"),
        "password_spray_mapper": (5, "Password Spray Surface Exposed"),
        "catchall_detector": (20, "Domain Is Parked / Not In Active Use"),
    }
```

No other change needed — the existing consuming loop (lines 177-184) already reads `mod_res.data.get("findings", [])` filtered by `severity in ("critical", "high")`, which Task 2's `catchall_detector` output already satisfies.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_scoring_catchall_penalty.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add yads/core/scoring.py tests/test_scoring_catchall_penalty.py
git commit -m "feat: deduct score for parked domains via existing generic-penalty hook"
```

---

## Task 5: Early, unconditional `catchall_detector` dispatch block in `run_all_scans`

**Files:**
- Modify: `yads/worker_tasks.py`
- Test: `tests/test_catchall_early_dispatch.py`

**Interfaces:**
- Consumes: `CatchallDetectorScanner` (unchanged import path), `tag_parked_domain` (Task 1), `LogCapture`/`sanitize_null_bytes` (already imported in this file).
- Produces: a local `is_parked: bool` variable inside `run_all_scans`, computed unconditionally (not gated on `scan_types`) whenever `has_http or has_https`. Tasks 6 and 7 consume this variable — it must exist by the time `_dispatch_module_chord` and the four custom-dispatch gates are reached in the function body.

- [ ] **Step 1: Read the current file to confirm exact structure**

Read `yads/worker_tasks.py` around the `has_http`/`has_https` pre-check (previously verified around lines 1173-1184, may have shifted — find by content: the `_needs_web` block ending in `logger.info(f"[Worker] Web Pre-check: HTTP={has_http}, HTTPS={has_https}")`) and the `# 1. Subdomain Scanner` block that follows it. Confirm `CatchallDetectorScanner`, `LogCapture`, `sanitize_null_bytes`, `session`, `target_id`, `domain` are all in scope at that point (they are, per the existing surrounding code — `session` is the open `Session(engine)` from the enclosing `with` block).

- [ ] **Step 2: Write the failing test**

```python
# tests/test_catchall_early_dispatch.py
"""
Verifies run_all_scans computes is_parked unconditionally (not gated on
scan_types) right after the has_http/has_https pre-check, and tags the
target when parked. This test targets the specific block added in this
task in isolation via monkeypatching, not a full run_all_scans execution
(that's covered by later tasks' integration test).
"""
from unittest.mock import patch, MagicMock


def test_catchall_pre_check_tags_target_when_parked():
    with patch("yads.worker_tasks.CatchallDetectorScanner") as mock_scanner_cls, \
         patch("yads.worker_tasks.tag_parked_domain") as mock_tag:
        mock_scanner = mock_scanner_cls.return_value
        mock_scanner.process.return_value = None
        mock_scanner.run_scan.return_value = {"is_catch_all": True, "matched_signature": "sedo"}

        # Exercise via the actual helper if Task 5 extracts one, or via a
        # minimal reproduction of the block's logic — see Step 3's exact
        # code. Import and call whatever name Step 3 actually defines.
        from yads.worker_tasks import _check_parked_domain
        session = MagicMock()
        is_parked = _check_parked_domain(session, 1, "example.com", has_http=True, has_https=False)

        assert is_parked is True
        mock_tag.assert_called_once_with(session, 1, "sedo")


def test_catchall_pre_check_not_parked_does_not_tag():
    with patch("yads.worker_tasks.CatchallDetectorScanner") as mock_scanner_cls, \
         patch("yads.worker_tasks.tag_parked_domain") as mock_tag:
        mock_scanner = mock_scanner_cls.return_value
        mock_scanner.process.return_value = None
        mock_scanner.run_scan.return_value = {"is_catch_all": False, "matched_signature": None}

        from yads.worker_tasks import _check_parked_domain
        session = MagicMock()
        is_parked = _check_parked_domain(session, 1, "example.com", has_http=True, has_https=False)

        assert is_parked is False
        mock_tag.assert_not_called()


def test_catchall_pre_check_uncertain_verdict_is_not_parked():
    with patch("yads.worker_tasks.CatchallDetectorScanner") as mock_scanner_cls, \
         patch("yads.worker_tasks.tag_parked_domain") as mock_tag:
        mock_scanner = mock_scanner_cls.return_value
        mock_scanner.process.return_value = None
        mock_scanner.run_scan.return_value = {"is_catch_all": None, "matched_signature": None}

        from yads.worker_tasks import _check_parked_domain
        session = MagicMock()
        is_parked = _check_parked_domain(session, 1, "example.com", has_http=True, has_https=False)

        assert is_parked is False
        mock_tag.assert_not_called()


def test_catchall_pre_check_skipped_when_no_http():
    with patch("yads.worker_tasks.CatchallDetectorScanner") as mock_scanner_cls:
        from yads.worker_tasks import _check_parked_domain
        session = MagicMock()
        is_parked = _check_parked_domain(session, 1, "example.com", has_http=False, has_https=False)

        assert is_parked is False
        mock_scanner_cls.assert_not_called()
```

This test drives a small extracted helper function, `_check_parked_domain`, rather than the inline block directly — extracting it keeps the logic unit-testable without mocking Celery/DB session machinery for the whole `run_all_scans` function. Define it as specified in Step 3.

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_catchall_early_dispatch.py -v`
Expected: FAIL — `ImportError: cannot import name '_check_parked_domain'`

- [ ] **Step 4: Modify `yads/worker_tasks.py`**

Add imports near the top of the file (with the other `yads.core.*`/`yads.modules.*` imports):

```python
from yads.modules.catchall_detector import CatchallDetectorScanner
from yads.core.parked_domain_tags import tag_parked_domain
```

Add a new module-level helper function, placed near the other small worker helpers (e.g. alongside `_dispatch_module_chord`, before `run_all_scans`):

```python
def _check_parked_domain(session, target_id: int, domain: str, has_http: bool, has_https: bool) -> bool:
    """
    Runs catchall_detector's live check and returns whether the domain is
    confirmed parked. An uncertain verdict (is_catch_all is None, e.g.
    unreachable) is never treated as parked. Tags the target via
    tag_parked_domain when parked. Does not persist a ScanResult itself —
    that's the caller's job (see run_all_scans), since this is meant to
    be called for the live gating decision independent of whether/when
    the module's own result gets saved.
    """
    if not (has_http or has_https):
        return False
    scanner = CatchallDetectorScanner(db_session=session)
    live_data = scanner.run_scan(domain, target_id=target_id)
    is_parked = live_data.get("is_catch_all") is True
    if is_parked:
        tag_parked_domain(session, target_id, live_data.get("matched_signature"))
    return is_parked
```

In `run_all_scans`, immediately after the existing `has_http`/`has_https` pre-check block (right after the line logging `f"[Worker] Web Pre-check: HTTP={has_http}, HTTPS={has_https}"`) and before the `# 1. Subdomain Scanner` block, insert:

```python
            # Catch-all / parked-domain pre-check — always runs (not gated
            # on scan_types) so the skip decision below is reliable
            # regardless of what the tenant selected; still shown as a
            # selectable module in the UI/scan profiles so its persisted
            # result is discoverable like any other module.
            logger.info(f"[Worker] Checking for parked/catch-all page on {domain}...")
            is_parked = _check_parked_domain(session, target_id, domain, has_http, has_https)

            catchall_scanner = CatchallDetectorScanner(db_session=session)
            with LogCapture() as logs:
                catchall_result = catchall_scanner.process(target_id, domain)
                captured_logs = logs.get_logs()
            if catchall_result and hasattr(catchall_result, 'log_content'):
                catchall_result.log_content = sanitize_null_bytes(captured_logs)
                session.add(catchall_result)
                session.commit()

            if is_parked:
                logger.info(f"[Worker] {domain} detected as parked — skipping content/app-analysis modules")
```

Note: this calls the module twice — once via `_check_parked_domain` (for the live gating decision, since `process()` only returns a `ScanResult` when the hash changed, which the gate needs every run regardless) and once via `.process()` (for the normal hash/diff/save persistence path every other custom-dispatch module uses). Both are single lightweight HTTP GETs; this matches the design spec's documented tradeoff.

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_catchall_early_dispatch.py -v`
Expected: PASS (4 tests)

- [ ] **Step 6: Commit**

```bash
git add yads/worker_tasks.py tests/test_catchall_early_dispatch.py
git commit -m "feat: run catchall_detector as an early, unconditional parked-domain check"
```

---

## Task 6: `_dispatch_module_chord` skips content/app-analysis modules when parked

**Files:**
- Modify: `yads/worker_tasks.py`
- Test: `tests/test_dispatch_chord_parked_skip.py`

**Interfaces:**
- Consumes: `is_parked` (Task 5, computed in `run_all_scans` before this function is called).
- Produces: `_dispatch_module_chord(target_id, domain, tenant_id, scan_types, has_http, has_https, is_parked, scan_start_time)` — new `is_parked` parameter inserted between `has_https` and `scan_start_time`; `PARKED_SKIP_MODULES: set` module-level constant.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_dispatch_chord_parked_skip.py
from unittest.mock import patch, MagicMock


def _mod(name, requires_http=False, requires_https=False):
    m = MagicMock()
    m.name = name
    m.requires_http = requires_http
    m.requires_https = requires_https
    return m


def test_parked_skips_content_app_analysis_modules():
    with patch("yads.worker_tasks.get_simple_dispatch_modules") as mock_get_mods, \
         patch("yads.worker_tasks.chord") as mock_chord, \
         patch("yads.worker_tasks.run_scan_module") as mock_run_scan_module, \
         patch("yads.worker_tasks.finalize_scan") as mock_finalize:
        mock_get_mods.return_value = [
            _mod("tech_stack_analyzer"),
            _mod("form_discovery", requires_http=True),
            _mod("api_discovery", requires_http=True),
            _mod("graphql_scanner", requires_http=True),
            _mod("websocket_scanner", requires_http=True),
            _mod("login_scanner", requires_http=True),
            _mod("password_spray_mapper", requires_http=True),
            _mod("dependency_confusion"),  # not in PARKED_SKIP_MODULES — must still run
        ]
        mock_run_scan_module.s.return_value = "sig"
        mock_chord.return_value = MagicMock()

        from yads.worker_tasks import _dispatch_module_chord
        scan_types = [
            "tech_stack_analyzer", "form_discovery", "api_discovery",
            "graphql_scanner", "websocket_scanner", "login_scanner",
            "password_spray_mapper", "dependency_confusion",
        ]
        _dispatch_module_chord(
            target_id=1, domain="example.com", tenant_id=42,
            scan_types=scan_types, has_http=True, has_https=True,
            is_parked=True, scan_start_time=None,
        )

        dispatched_names = [call.args[2] for call in mock_run_scan_module.s.call_args_list]
        assert dispatched_names == ["dependency_confusion"]


def test_not_parked_dispatches_all_selected_modules():
    with patch("yads.worker_tasks.get_simple_dispatch_modules") as mock_get_mods, \
         patch("yads.worker_tasks.chord") as mock_chord, \
         patch("yads.worker_tasks.run_scan_module") as mock_run_scan_module, \
         patch("yads.worker_tasks.finalize_scan"):
        mock_get_mods.return_value = [_mod("form_discovery", requires_http=True), _mod("dependency_confusion")]
        mock_run_scan_module.s.return_value = "sig"
        mock_chord.return_value = MagicMock()

        from yads.worker_tasks import _dispatch_module_chord
        _dispatch_module_chord(
            target_id=1, domain="example.com", tenant_id=42,
            scan_types=["form_discovery", "dependency_confusion"], has_http=True, has_https=True,
            is_parked=False, scan_start_time=None,
        )

        dispatched_names = [call.args[2] for call in mock_run_scan_module.s.call_args_list]
        assert set(dispatched_names) == {"form_discovery", "dependency_confusion"}


def test_parked_skip_module_set_matches_spec():
    from yads.worker_tasks import PARKED_SKIP_MODULES
    assert PARKED_SKIP_MODULES == {
        "tech_stack_analyzer", "form_discovery", "api_discovery",
        "graphql_scanner", "websocket_scanner", "login_scanner",
        "password_spray_mapper",
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_dispatch_chord_parked_skip.py -v`
Expected: FAIL — `_dispatch_module_chord() missing 1 required positional argument: 'is_parked'` (and `PARKED_SKIP_MODULES` doesn't exist)

- [ ] **Step 3: Modify `yads/worker_tasks.py`**

Add the module-level constant near `_dispatch_module_chord`'s definition:

```python
PARKED_SKIP_MODULES = {
    "tech_stack_analyzer", "form_discovery", "api_discovery",
    "graphql_scanner", "websocket_scanner", "login_scanner",
    "password_spray_mapper",
}
```

Modify `_dispatch_module_chord`'s signature and selection loop:

```python
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

(Leave the rest of the function — the empty-list `finalize_scan` short-circuit, chord construction — unchanged.)

Update the call site inside `run_all_scans` (currently `_dispatch_module_chord(target_id, domain, tenant_id, scan_types, has_http, has_https, scan_start_time)`, using `parent_tenant_id` per the prior branch's fix) to pass `is_parked` (the variable computed in Task 5) as the new positional argument, in the same position as the signature above:

```python
            _dispatch_module_chord(
                target_id, domain, parent_tenant_id, scan_types, has_http, has_https, is_parked, scan_start_time,
            )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_dispatch_chord_parked_skip.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add yads/worker_tasks.py tests/test_dispatch_chord_parked_skip.py
git commit -m "feat: skip content/app-analysis modules in chord dispatch when domain is parked"
```

---

## Task 7: Custom-dispatch gates for `crawler`/`visual_osint`/`content_discovery`/`nuclei_scanner`

**Files:**
- Modify: `yads/worker_tasks.py`
- Test: `tests/test_custom_dispatch_parked_gates.py`

**Interfaces:**
- Consumes: `is_parked` (Task 5).
- Produces: each of the four modules' existing `if "<name>" in scan_types and ...` gate condition gains `and not is_parked`.

- [ ] **Step 1: Read the current file to find each gate's exact current condition**

Read `yads/worker_tasks.py` and locate the four hardcoded dispatch blocks for `crawler`, `visual_osint`, `content_discovery`, and `nuclei_scanner` (search for `"crawler" in scan_types`, `"visual_osint" in scan_types`, `"content_discovery" in scan_types`, `"nuclei_scanner" in scan_types` — each appears once as an `if` condition gating that module's block). Note each one's exact current condition text (they likely each check `(has_http or has_https)` alongside the `scan_types` membership, following the same shape as the `content_discovery` example already seen: `if "content_discovery" in scan_types and (has_http or has_https):`).

- [ ] **Step 2: Write the failing tests**

```python
# tests/test_custom_dispatch_parked_gates.py
"""
Confirms the four custom-dispatch modules' worker_tasks.py source each
include an `is_parked` exclusion in their gate condition. This is a
source-scan test (like tests/test_public_api_service_names.py from the
scan-queue-rate-limit-resilience branch) rather than an execution test,
since exercising the real run_all_scans function requires a live DB/
Celery context impractical to fully mock for four separate blocks.
"""
import re
from pathlib import Path

YADS_ROOT = Path(__file__).resolve().parents[1] / "yads"

GATED_MODULES = ["crawler", "visual_osint", "content_discovery", "nuclei_scanner"]


def test_each_gate_excludes_parked_domains():
    src = (YADS_ROOT / "worker_tasks.py").read_text()
    for name in GATED_MODULES:
        pattern = re.compile(rf'if\s+"{name}"\s+in\s+scan_types[^:]*:', re.MULTILINE)
        match = pattern.search(src)
        assert match, f"could not find dispatch gate for {name}"
        assert "not is_parked" in match.group(0), (
            f"{name}'s gate condition does not exclude parked domains: {match.group(0)!r}"
        )
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_custom_dispatch_parked_gates.py -v`
Expected: FAIL — 4 assertion failures (or however many gates are found without `not is_parked`)

- [ ] **Step 4: Modify `yads/worker_tasks.py`**

For each of the four gate conditions found in Step 1, add `and not is_parked` to the existing condition. For example, if `content_discovery`'s gate currently reads:

```python
            if "content_discovery" in scan_types and (has_http or has_https):
```

change it to:

```python
            if "content_discovery" in scan_types and (has_http or has_https) and not is_parked:
```

Apply the identical pattern (append `and not is_parked` to the existing `if` condition, preserving whatever other conditions are already there) to the `crawler`, `visual_osint`, and `nuclei_scanner` gates — read each one's actual current condition from Step 1 and adapt precisely; do not assume they're textually identical to the `content_discovery` example.

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_custom_dispatch_parked_gates.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add yads/worker_tasks.py tests/test_custom_dispatch_parked_gates.py
git commit -m "feat: skip crawler/visual_osint/content_discovery/nuclei_scanner on parked domains"
```

---

## Task 8: Tags column in the target-list export

**Files:**
- Modify: `yads/api/routers/reports.py`
- Test: `tests/test_reports_export_tags_column.py`

**Interfaces:**
- Consumes: `Target.tags` (existing field, no change).
- Produces: `_get_targets_data(..., for_export=True)`'s returned dicts include a `"Tags"` key; `export_targets_csv`'s header row and each data row include the same column, in the same relative position.

- [ ] **Step 1: Read the current file to confirm exact structure**

Read `yads/api/routers/reports.py`'s `_get_targets_data()` function and the `export_targets_csv` route in full, to confirm the exact current header/row-building code (previously verified: `_get_targets_data` at lines 27-52, dict literal with `ID`/`Domain`/`Created At`/`Last Scan`/`Status`; `export_targets_csv` separately builds `writer.writerow(['ID', 'Domain', 'Created At', 'Last Scan', 'Status'])` and per-row `writer.writerow([t.id, t.domain, ...])` — confirm these haven't shifted).

- [ ] **Step 2: Write the failing tests**

```python
# tests/test_reports_export_tags_column.py
"""
Verifies the target-list export (both the dict-based Excel/PDF path via
_get_targets_data and the CSV route's inline column building) include a
Tags column sourced from Target.tags.
"""
from unittest.mock import MagicMock
from datetime import datetime


def _mock_target(id=1, domain="example.com", tags=None):
    t = MagicMock()
    t.id = id
    t.domain = domain
    t.created_at = datetime(2026, 1, 1, 12, 0, 0)
    t.scan_status = "idle"
    t.tags = tags or []
    return t


def test_get_targets_data_includes_tags_column():
    from yads.api.routers.reports import _get_targets_data

    mock_session = MagicMock()
    mock_session.exec.return_value.all.return_value = [_mock_target(tags=["sedoparking", "customer-a"])]
    mock_session.exec.return_value.first.return_value = None  # no ScanResult -> "Never"
    mock_user = MagicMock(tenant_id=None, role="admin")

    data = _get_targets_data(mock_session, mock_user, for_export=True)

    assert len(data) == 1
    assert data[0]["Tags"] == "sedoparking, customer-a"


def test_get_targets_data_empty_tags_renders_empty_string():
    from yads.api.routers.reports import _get_targets_data

    mock_session = MagicMock()
    mock_session.exec.return_value.all.return_value = [_mock_target(tags=[])]
    mock_session.exec.return_value.first.return_value = None
    mock_user = MagicMock(tenant_id=None, role="admin")

    data = _get_targets_data(mock_session, mock_user, for_export=True)

    assert data[0]["Tags"] == ""
```

If `_get_targets_data`'s actual signature or the mocking shape needed for `session.exec(...)` differs from this (e.g. it's called with different chained methods), adjust the mock setup to match what Step 1's reading reveals — the assertions on the `"Tags"` key's presence and value are what this task verifies.

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_reports_export_tags_column.py -v`
Expected: FAIL — `KeyError: 'Tags'`

- [ ] **Step 4: Modify `yads/api/routers/reports.py`**

In `_get_targets_data()`'s export-dict branch, add a `"Tags"` key to the dict literal:

```python
        export_data.append({
            "ID": t.id,
            "Domain": t.domain,
            "Created At": t.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "Last Scan": last_scan,
            "Status": t.scan_status,
            "Tags": ", ".join(t.tags),
        })
```

In `export_targets_csv`, add the same column to the header row:

```python
    writer.writerow(['ID', 'Domain', 'Created At', 'Last Scan', 'Status', 'Tags'])
```

and to each data row (find the corresponding `writer.writerow([t.id, t.domain, ...])` call and append `", ".join(t.tags)` as the final element, matching whatever variable holds the "Last Scan"/"Status" values at that point in the loop).

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_reports_export_tags_column.py -v`
Expected: PASS (2 tests)

- [ ] **Step 6: Commit**

```bash
git add yads/api/routers/reports.py tests/test_reports_export_tags_column.py
git commit -m "feat: add Tags column to target-list CSV/Excel/PDF export"
```

---

## Task 9: Full regression pass

**Files:** none (verification-only task)

- [ ] **Step 1: Run the full test suite**

Run: `pytest tests/ -v`
Expected: All tests pass (pre-existing environment-specific failures — missing test Postgres, `release_lib`/`debug_scripts` import gaps — are expected and documented in this repo's prior branch history; confirm any failures seen match that known set rather than being new).

- [ ] **Step 2: Run every test file this plan added or touched, explicitly**

Run: `pytest tests/test_parked_domain_tags.py tests/test_catchall_detector_findings.py tests/test_catchall_detector_registry.py tests/test_scoring_catchall_penalty.py tests/test_catchall_early_dispatch.py tests/test_dispatch_chord_parked_skip.py tests/test_custom_dispatch_parked_gates.py tests/test_reports_export_tags_column.py -v`
Expected: All pass, pristine output.

- [ ] **Step 3: Manual smoke check (if a running dev stack is available)**

Trigger a scan against a domain known to serve a Sedo/GoDaddy parking page (or a `responses`-mocked equivalent), and confirm: the target gains the expected tag (visible in the target list's tag filter dropdown), the security score reflects the deduction, `crawler`/`content_discovery`/`nuclei_scanner`/etc. are absent from that scan's module list in the queue/logs, and a CSV export of the target list includes the tag in its `Tags` column.

- [ ] **Step 4: Commit (only if Steps 1-3 required fixes)**

```bash
git add -A
git commit -m "fix: address regressions found in full test suite pass"
```
