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

        watch = BrandWatch(tenant_id=test_tenant.id, keyword="acmecorp")
        db_session.add(watch)
        db_session.commit()
        db_session.refresh(watch)

        assert watch.id is not None
        assert watch.active is True

        candidate = ShadowDomainCandidate(
            brand_watch_id=watch.id,
            tenant_id=test_tenant.id,
            discovered_domain="acmecorp-portal.example",
            source="ct_log",
        )
        db_session.add(candidate)
        db_session.commit()
        db_session.refresh(candidate)

        assert candidate.status == "new"
        assert candidate.resolved_target_id is None

        # Clean up: delete candidate first (child), then watch (parent)
        db_session.query(ShadowDomainCandidate).filter_by(brand_watch_id=watch.id).delete()
        db_session.delete(watch)
        db_session.commit()

    def test_shadow_domain_candidate_unique_per_watch_and_domain(self, db_session, test_tenant):
        from yads.models import BrandWatch, ShadowDomainCandidate
        from sqlalchemy.exc import IntegrityError

        watch = BrandWatch(tenant_id=test_tenant.id, keyword="acmecorp")
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
        created_target = None
        if not target:
            target = Target(domain="wizard-step1-test.example.com", tenant_id=test_tenant.id)
            db_session.add(target)
            db_session.commit()
            db_session.refresh(target)
            created_target = target

        run = None
        try:
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
            assert run.created_by_user_id is not None  # finding #4: must be populated
        finally:
            if run:
                db_session.delete(run)
                db_session.commit()
            if created_target:
                db_session.delete(created_target)
                db_session.commit()

    def test_effective_tenant_id_ambiguous_with_multiple_tenants(self, admin_client, db_session):
        """When a platform admin (user.tenant_id is None) has no unambiguous
        single tenant to fall back to -- i.e. more than one Tenant row exists
        -- _effective_tenant_id must return None, and start_run must refuse
        with 400 rather than guessing which tenant to scope the run to."""
        from yads.models import Tenant, User
        from yads.api.routers.compliance_wizard import _effective_tenant_id
        from sqlmodel import select

        extra_tenant = Tenant(name="Second Test Tenant")
        db_session.add(extra_tenant)
        db_session.commit()
        db_session.refresh(extra_tenant)

        try:
            admin_user = db_session.exec(
                select(User).where(User.username == "admin")
            ).first()
            assert admin_user.tenant_id is None

            assert _effective_tenant_id(db_session, admin_user) is None

            r = admin_client.post(
                "/compliance-wizard/start",
                data={"criteria": "all"},
                follow_redirects=True,
            )
            assert r.status_code == 400
        finally:
            db_session.delete(extra_tenant)
            db_session.commit()


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

        try:
            r = admin_client.post(f"/compliance-wizard/{run.id}/step2", follow_redirects=True)
            assert r.status_code < 500

            db_session.refresh(run)
            assert run.current_step == 3
        finally:
            db_session.delete(run)
            db_session.delete(target)
            db_session.commit()


@pytest.mark.compliance_wizard
class TestWizardStep3Progress:
    def test_targets_crawled_computed_on_dashboard_load(self, admin_client, test_tenant, db_session):
        """Finding #3: targets_crawled was never computed, so the dashboard
        permanently showed 0 even after crawler ScanResults existed."""
        from yads.models import Target, ComplianceScanRun, ScanResult
        from sqlmodel import select

        crawled = Target(domain="wizard-step3-crawled.example.com", tenant_id=test_tenant.id)
        not_crawled = Target(domain="wizard-step3-not-crawled.example.com", tenant_id=test_tenant.id)
        db_session.add(crawled)
        db_session.add(not_crawled)
        db_session.commit()
        db_session.refresh(crawled)
        db_session.refresh(not_crawled)

        db_session.add(ScanResult(
            target_id=crawled.id, module_name="crawler",
            data={"pages": 3}, result_hash="y",
        ))
        db_session.commit()

        run = ComplianceScanRun(
            tenant_id=test_tenant.id, criteria="all", current_step=4,
            target_ids=[crawled.id, not_crawled.id], targets_total=2,
        )
        db_session.add(run)
        db_session.commit()
        db_session.refresh(run)

        try:
            r = admin_client.get("/compliance-wizard", follow_redirects=True)
            assert r.status_code == 200

            db_session.refresh(run)
            assert run.targets_crawled == 1
        finally:
            db_session.delete(run)
            db_session.query(ScanResult).filter_by(target_id=crawled.id).delete()
            db_session.delete(crawled)
            db_session.delete(not_crawled)
            db_session.commit()


@pytest.mark.compliance_wizard
class TestWizardStep3:
    def test_step3_dispatch_only_targets_webserver_confirmed_subset(self, admin_client, test_tenant, db_session, monkeypatch):
        from yads.models import Target, ComplianceScanRun, ScanResult
        from yads.api.routers import targets as targets_module
        from sqlmodel import select

        # This test env has no reachable Celery broker (BROKER_URL defaults to
        # an unreachable rabbitmq host), so _queue_single_bulk_target's real
        # send_task would raise and scan_status would never flip to "queued"
        # regardless of scoping. Stub send_task so we can assert the actual
        # behavior under test: which targets get queued.
        monkeypatch.setattr(targets_module.celery_app, "send_task", lambda *a, **kw: None)

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

        try:
            r = admin_client.post(f"/compliance-wizard/{run.id}/step3", follow_redirects=True)
            assert r.status_code < 500

            db_session.refresh(run)
            assert run.current_step == 4

            # The single most safety-relevant property of the wizard: step 3
            # must only queue crawls for the webserver-confirmed subset, never
            # the full target set. _queue_single_bulk_target sets
            # scan_status="queued" on targets it successfully dispatches, so
            # assert the confirmed target WAS queued and the non-confirmed
            # target was NOT (still its original "idle" status).
            db_session.refresh(with_server)
            db_session.refresh(without_server)
            assert with_server.scan_status == "queued"
            assert without_server.scan_status == "idle"
        finally:
            db_session.delete(run)
            db_session.query(ScanResult).filter_by(target_id=with_server.id).delete()
            db_session.delete(with_server)
            db_session.delete(without_server)
            db_session.commit()


@pytest.mark.compliance_wizard
class TestNewRunAfterStep3:
    def test_new_run_button_visible_once_step3_completed(self, admin_client, test_tenant, db_session):
        """Finding #6: spec requires a way to start a new run once the
        existing run's step 3 has finished (e.g. quarterly re-scan)."""
        from datetime import datetime
        from yads.models import ComplianceScanRun

        run = ComplianceScanRun(
            tenant_id=test_tenant.id, criteria="all", current_step=4, target_ids=[],
            step3_completed_at=datetime.utcnow(),
        )
        db_session.add(run)
        db_session.commit()
        db_session.refresh(run)

        try:
            r = admin_client.get("/compliance-wizard", follow_redirects=True)
            assert r.status_code == 200
            assert "/compliance-wizard/start" in r.text
            assert "Start a new run" in r.text
        finally:
            db_session.delete(run)
            db_session.commit()


@pytest.mark.compliance_wizard
class TestWizardStep4:
    def test_step4_creates_brand_watch(self, admin_client, test_tenant, db_session):
        from yads.models import ComplianceScanRun, BrandWatch
        from sqlmodel import select

        run = ComplianceScanRun(tenant_id=test_tenant.id, criteria="all", current_step=4, target_ids=[])
        db_session.add(run)
        db_session.commit()
        db_session.refresh(run)

        try:
            r = admin_client.post(
                f"/compliance-wizard/{run.id}/step4",
                data={"keyword": "acmecorp"},
                follow_redirects=True,
            )
            assert r.status_code == 200

            watch = db_session.exec(
                select(BrandWatch).where(BrandWatch.tenant_id == test_tenant.id, BrandWatch.keyword == "acmecorp")
            ).first()
            assert watch is not None
            assert watch.active is True
        finally:
            from yads.models import ShadowDomainCandidate
            watch = db_session.exec(
                select(BrandWatch).where(BrandWatch.tenant_id == test_tenant.id, BrandWatch.keyword == "acmecorp")
            ).first()
            if watch:
                db_session.query(ShadowDomainCandidate).filter_by(brand_watch_id=watch.id).delete()
                db_session.delete(watch)
            db_session.delete(run)
            db_session.commit()

    def test_step4_double_submit_does_not_create_duplicate_brand_watch(self, admin_client, test_tenant, db_session):
        """Finding #7: double-submitting step 4 (double-click, retry) must not
        create a second BrandWatch with the same (tenant_id, keyword), and the
        run must reach a terminal state so the form stops re-rendering."""
        from yads.models import ComplianceScanRun, BrandWatch
        from sqlmodel import select

        run = ComplianceScanRun(tenant_id=test_tenant.id, criteria="all", current_step=4, target_ids=[])
        db_session.add(run)
        db_session.commit()
        db_session.refresh(run)

        try:
            r1 = admin_client.post(
                f"/compliance-wizard/{run.id}/step4",
                data={"keyword": "acmecorp-dupe-test"},
                follow_redirects=True,
            )
            assert r1.status_code == 200

            db_session.refresh(run)
            assert run.current_step >= 5  # terminal marker past step 4

            r2 = admin_client.post(
                f"/compliance-wizard/{run.id}/step4",
                data={"keyword": "acmecorp-dupe-test"},
                follow_redirects=True,
            )
            assert r2.status_code == 200

            watches = db_session.exec(
                select(BrandWatch).where(
                    BrandWatch.tenant_id == test_tenant.id,
                    BrandWatch.keyword == "acmecorp-dupe-test",
                )
            ).all()
            assert len(watches) == 1
        finally:
            from yads.models import ShadowDomainCandidate
            watches = db_session.exec(
                select(BrandWatch).where(
                    BrandWatch.tenant_id == test_tenant.id,
                    BrandWatch.keyword == "acmecorp-dupe-test",
                )
            ).all()
            for w in watches:
                db_session.query(ShadowDomainCandidate).filter_by(brand_watch_id=w.id).delete()
                db_session.delete(w)
            db_session.delete(run)
            db_session.commit()

    def test_step4_nonexistent_run_does_not_create_brand_watch(self, admin_client, test_tenant, db_session):
        from yads.models import BrandWatch
        from sqlmodel import select

        nonexistent_run_id = 999_999

        try:
            r = admin_client.post(
                f"/compliance-wizard/{nonexistent_run_id}/step4",
                data={"keyword": "acmecorp-nonexistent-run"},
                follow_redirects=True,
            )
            assert r.status_code == 200

            watch = db_session.exec(
                select(BrandWatch).where(
                    BrandWatch.tenant_id == test_tenant.id,
                    BrandWatch.keyword == "acmecorp-nonexistent-run",
                )
            ).first()
            assert watch is None
        finally:
            watch = db_session.exec(
                select(BrandWatch).where(
                    BrandWatch.tenant_id == test_tenant.id,
                    BrandWatch.keyword == "acmecorp-nonexistent-run",
                )
            ).first()
            if watch:
                db_session.delete(watch)
                db_session.commit()


@pytest.mark.compliance_wizard
class TestBrandWatchScan:
    def test_ct_search_keyword_parses_crtsh_response(self, monkeypatch):
        from yads import worker_tasks

        class FakeResponse:
            status_code = 200
            def json(self):
                return [
                    {"name_value": "portal.acmecorp-example.com\nwww.acmecorp-example.com"},
                    {"name_value": "unrelated-nothing.example.org"},
                ]

        class FakeClient:
            def register_service(self, *a, **kw):
                pass
            def get(self, service_name, url, **kw):
                assert "acmecorp" in url
                return FakeResponse()

        # _ct_search_keyword uses a module-level singleton client (so rate
        # limiting is actually shared/effective across calls), not a fresh
        # RateLimitedClient() per call -- patch the singleton directly.
        monkeypatch.setattr(worker_tasks, "_brand_watch_ct_client", FakeClient())

        domains = worker_tasks._ct_search_keyword("acmecorp")
        assert "portal.acmecorp-example.com" in domains
        assert "www.acmecorp-example.com" in domains
        assert "unrelated-nothing.example.org" not in domains

    def test_ct_search_keyword_url_encodes_special_characters(self, monkeypatch):
        """A keyword containing '&', '#', or whitespace must not break the
        crt.sh query string or inject extra query parameters."""
        from yads import worker_tasks

        class FakeResponse:
            status_code = 200
            def json(self):
                return []

        captured_urls = []

        class FakeClient:
            def register_service(self, *a, **kw):
                pass
            def get(self, service_name, url, **kw):
                captured_urls.append(url)
                return FakeResponse()

        monkeypatch.setattr(worker_tasks, "_brand_watch_ct_client", FakeClient())

        worker_tasks._ct_search_keyword("example corp & co #test")

        assert len(captured_urls) == 1
        url = captured_urls[0]
        assert "&" not in url.split("?q=", 1)[1] or "%26" in url
        assert " " not in url
        assert "#" not in url
        assert url.count("q=") == 1  # a raw '&' would have injected a second/garbled param

    def test_run_brand_watch_scan_creates_candidates_and_skips_known_targets(self, monkeypatch, db_session, test_tenant):
        from yads import worker_tasks
        from yads.models import BrandWatch, ShadowDomainCandidate, Target
        from sqlmodel import select

        known = Target(domain="acmecorp-known.example.com", tenant_id=test_tenant.id)
        db_session.add(known)
        db_session.commit()
        db_session.refresh(known)

        watch = BrandWatch(tenant_id=test_tenant.id, keyword="acmecorp")
        db_session.add(watch)
        db_session.commit()
        db_session.refresh(watch)

        monkeypatch.setattr(worker_tasks, "_ct_search_keyword", lambda kw: ["acmecorp-known.example.com", "acmecorp-shadow.example.net"])
        monkeypatch.setattr(worker_tasks, "_probe_keyword_across_tlds", lambda kw: ["acmecorp.info"])

        try:
            worker_tasks.run_brand_watch_scan()

            candidates = db_session.exec(
                select(ShadowDomainCandidate).where(ShadowDomainCandidate.brand_watch_id == watch.id)
            ).all()
            discovered = {c.discovered_domain for c in candidates}

            assert "acmecorp-shadow.example.net" in discovered
            assert "acmecorp.info" in discovered
            assert "acmecorp-known.example.com" not in discovered  # already a known Target, not a candidate
        finally:
            candidates = db_session.exec(
                select(ShadowDomainCandidate).where(ShadowDomainCandidate.brand_watch_id == watch.id)
            ).all()
            for c in candidates:
                db_session.delete(c)
            db_session.commit()
            db_session.delete(watch)
            db_session.delete(known)
            db_session.commit()


    def test_run_brand_watch_scan_updates_last_seen_at_on_rediscovery(self, monkeypatch, db_session, test_tenant):
        """Finding #2: re-discovering an already-known candidate (any status)
        must update last_seen_at rather than being silently skipped -- this is
        what lets a human judge a re-appearance against the original
        dismissal reasoning."""
        from datetime import datetime, timedelta
        from yads import worker_tasks
        from yads.models import BrandWatch, ShadowDomainCandidate
        from sqlmodel import select

        watch = BrandWatch(tenant_id=test_tenant.id, keyword="acmecorp")
        db_session.add(watch)
        db_session.commit()
        db_session.refresh(watch)

        old_time = datetime.utcnow() - timedelta(days=30)
        candidate = ShadowDomainCandidate(
            brand_watch_id=watch.id, tenant_id=test_tenant.id,
            discovered_domain="acmecorp-rediscovered.example.net", source="ct_log",
            status="dismissed", dismissed_reason="false positive",
            first_seen_at=old_time, last_seen_at=old_time,
        )
        db_session.add(candidate)
        db_session.commit()
        db_session.refresh(candidate)

        monkeypatch.setattr(worker_tasks, "_ct_search_keyword", lambda kw: ["acmecorp-rediscovered.example.net"])
        monkeypatch.setattr(worker_tasks, "_probe_keyword_across_tlds", lambda kw: [])

        try:
            worker_tasks.run_brand_watch_scan()

            db_session.refresh(candidate)
            assert candidate.last_seen_at > old_time
            # Re-discovery must not clobber the dismissal itself.
            assert candidate.status == "dismissed"

            all_candidates = db_session.exec(
                select(ShadowDomainCandidate).where(ShadowDomainCandidate.brand_watch_id == watch.id)
            ).all()
            assert len(all_candidates) == 1  # no duplicate row created
        finally:
            db_session.delete(candidate)
            db_session.commit()
            db_session.delete(watch)
            db_session.commit()


@pytest.mark.compliance_wizard
class TestTriage:
    def _make_candidate(self, db_session, test_tenant, domain="acmecorp-triage-test.example.net"):
        from yads.models import BrandWatch, ShadowDomainCandidate

        watch = BrandWatch(tenant_id=test_tenant.id, keyword="acmecorp")
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

        try:
            r = admin_client.post(f"/compliance-wizard/shadow-domains/{candidate.id}/confirm", follow_redirects=True)
            assert r.status_code == 200

            db_session.refresh(candidate)
            assert candidate.status == "confirmed"
            assert candidate.resolved_target_id is not None

            created_target = db_session.exec(
                select(Target).where(Target.id == candidate.resolved_target_id)
            ).first()
            assert created_target.domain == "acmecorp-triage-test.example.net"
        finally:
            db_session.refresh(candidate)
            created_target = None
            if candidate.resolved_target_id is not None:
                created_target = db_session.exec(
                    select(Target).where(Target.id == candidate.resolved_target_id)
                ).first()
            db_session.delete(candidate)
            if created_target:
                db_session.delete(created_target)
            db_session.commit()
            db_session.delete(watch)
            db_session.commit()

    def test_confirm_cross_tenant_domain_collision_returns_error_not_crash(self, admin_client, test_tenant, db_session, monkeypatch):
        """Target.domain has a GLOBAL unique constraint, but run_brand_watch_scan
        only diffs against Targets for the SAME tenant -- so a domain already
        owned by a DIFFERENT tenant can surface as a "new" candidate. Confirming
        it must not crash with an uncaught IntegrityError, must not create a
        duplicate Target, and must not silently mark the candidate confirmed."""
        from yads.models import Tenant, Target, BrandWatch, ShadowDomainCandidate
        from yads.api.routers import compliance_wizard as cw_module
        from sqlmodel import select

        other_tenant = Tenant(name="Cross Tenant Collision Test Tenant")
        db_session.add(other_tenant)
        db_session.commit()
        db_session.refresh(other_tenant)

        collision_domain = "cross-tenant-collision-test.example.net"
        other_target = Target(domain=collision_domain, tenant_id=other_tenant.id)
        db_session.add(other_target)
        db_session.commit()
        db_session.refresh(other_target)

        watch = BrandWatch(tenant_id=test_tenant.id, keyword="acmecorp")
        db_session.add(watch)
        db_session.commit()
        db_session.refresh(watch)

        candidate = ShadowDomainCandidate(
            brand_watch_id=watch.id, tenant_id=test_tenant.id,
            discovered_domain=collision_domain, source="ct_log",
        )
        db_session.add(candidate)
        db_session.commit()
        db_session.refresh(candidate)

        # admin_client's user has tenant_id=None; with two Tenant rows now
        # present, _effective_tenant_id's single-tenant auto-resolve is
        # ambiguous. Pin it to test_tenant so this test exercises the
        # cross-tenant-collision branch specifically, not the ambiguity path
        # covered by test_effective_tenant_id_ambiguous_with_multiple_tenants.
        monkeypatch.setattr(cw_module, "_effective_tenant_id", lambda session, user: test_tenant.id)

        try:
            r = admin_client.post(f"/compliance-wizard/shadow-domains/{candidate.id}/confirm", follow_redirects=True)
            assert r.status_code < 500
            assert r.status_code in (400, 409)

            db_session.refresh(candidate)
            assert candidate.status == "new"
            assert candidate.resolved_target_id is None

            all_targets_with_domain = db_session.exec(
                select(Target).where(Target.domain == collision_domain)
            ).all()
            assert len(all_targets_with_domain) == 1
            assert all_targets_with_domain[0].id == other_target.id
        finally:
            db_session.delete(candidate)
            db_session.commit()
            db_session.delete(watch)
            db_session.delete(other_target)
            db_session.commit()
            db_session.delete(other_tenant)
            db_session.commit()

    def test_dismiss_sets_reason_and_status(self, admin_client, test_tenant, db_session):
        watch, candidate = self._make_candidate(db_session, test_tenant, domain="acmecorp-dismiss-test.example.net")

        try:
            r = admin_client.post(
                f"/compliance-wizard/shadow-domains/{candidate.id}/dismiss",
                data={"reason": "unrelated third party, false positive substring match"},
                follow_redirects=True,
            )
            assert r.status_code == 200

            db_session.refresh(candidate)
            assert candidate.status == "dismissed"
            assert "false positive" in candidate.dismissed_reason
        finally:
            db_session.delete(candidate)
            db_session.commit()
            db_session.delete(watch)
            db_session.commit()

    def test_confirm_toctou_race_handled_gracefully(self, app, admin_client, test_tenant, db_session, monkeypatch):
        """Between confirm_shadow_domain's existing_target check and its own
        Target insert, a concurrent request can win the race and insert the
        same domain for a DIFFERENT tenant first -- Target.domain's unique
        constraint then makes our insert raise IntegrityError. This must be
        caught and handled (re-fetch + correct-tenant-check), not crash."""
        from yads.database import get_session, engine
        from yads.models import Tenant, Target, BrandWatch, ShadowDomainCandidate
        from yads.api.routers import compliance_wizard as cw_module
        from sqlmodel import Session as SQLModelSession, select
        from sqlalchemy.exc import IntegrityError

        other_tenant = Tenant(name="TOCTOU Race Test Other Tenant")
        db_session.add(other_tenant)
        db_session.commit()
        db_session.refresh(other_tenant)

        # Pin tenant resolution deterministically: with a second Tenant row
        # now present, admin's own single-tenant auto-resolve fallback would
        # become ambiguous (returns None) -- not what this test is about.
        monkeypatch.setattr(cw_module, "_effective_tenant_id", lambda session, user: test_tenant.id)

        watch = BrandWatch(tenant_id=test_tenant.id, keyword="acmecorp")
        db_session.add(watch)
        db_session.commit()
        db_session.refresh(watch)

        domain = "acmecorp-toctou-race-test.example.net"
        candidate = ShadowDomainCandidate(
            brand_watch_id=watch.id, tenant_id=test_tenant.id,
            discovered_domain=domain, source="ct_log",
        )
        db_session.add(candidate)
        db_session.commit()
        db_session.refresh(candidate)

        # Override the request-scoped session with one whose first commit()
        # simulates losing the race: a separate connection inserts the same
        # domain for `other_tenant` right then, and this commit fails exactly
        # like Postgres's real unique-constraint violation would.
        def flaky_get_session():
            with SQLModelSession(engine) as session:
                original_commit = session.commit
                state = {"raised": False}

                def commit_once_failing():
                    if not state["raised"]:
                        state["raised"] = True
                        with SQLModelSession(engine) as other:
                            other.add(Target(domain=domain, tenant_id=other_tenant.id))
                            other.commit()
                        raise IntegrityError("INSERT", {}, Exception(
                            "duplicate key value violates unique constraint"
                        ))
                    return original_commit()

                session.commit = commit_once_failing
                yield session

        app.dependency_overrides[get_session] = flaky_get_session
        try:
            r = admin_client.post(f"/compliance-wizard/shadow-domains/{candidate.id}/confirm", follow_redirects=True)
        finally:
            del app.dependency_overrides[get_session]

        try:
            assert r.status_code < 500
            assert r.status_code == 409

            db_session.refresh(candidate)
            assert candidate.status == "new"
            assert candidate.resolved_target_id is None

            targets_with_domain = db_session.exec(select(Target).where(Target.domain == domain)).all()
            assert len(targets_with_domain) == 1
            assert targets_with_domain[0].tenant_id == other_tenant.id
        finally:
            db_session.delete(candidate)
            db_session.commit()
            db_session.delete(watch)
            for t in db_session.exec(select(Target).where(Target.domain == domain)).all():
                db_session.delete(t)
            db_session.commit()
            db_session.delete(other_tenant)
            db_session.commit()


@pytest.mark.compliance_wizard
class TestAuditLogTenantResolution:
    """_audit_scan_trigger reads user.tenant_id directly, which is None for
    a platform admin -- exactly the case _effective_tenant_id exists to
    resolve. start_run/dispatch_step2/dispatch_step3 must pass a
    tenant-resolved stand-in, not the raw user, so the DORA audit trail
    never carries a NULL tenant_id for these events."""

    def test_wizard_dispatch_audit_logs_have_resolved_tenant_id(self, app, admin_client, test_tenant, db_session, monkeypatch):
        from yads.models import SecurityAuditLog, Target, ComplianceScanRun, ScanResult
        from yads.api.routers import compliance_wizard as cw_module
        from sqlmodel import select

        # Pin tenant resolution deterministically regardless of how many
        # Tenant rows exist in the shared test DB at this point.
        monkeypatch.setattr(cw_module, "_effective_tenant_id", lambda session, user: test_tenant.id)

        target = Target(domain="audit-tenant-resolution-test.example.com", tenant_id=test_tenant.id)
        db_session.add(target)
        db_session.commit()
        db_session.refresh(target)

        run = None
        try:
            r = admin_client.post("/compliance-wizard/start", data={"criteria": "all"}, follow_redirects=True)
            assert r.status_code == 200

            run = db_session.exec(
                select(ComplianceScanRun).where(ComplianceScanRun.tenant_id == test_tenant.id)
                .order_by(ComplianceScanRun.id.desc())
            ).first()
            assert run is not None

            r2 = admin_client.post(f"/compliance-wizard/{run.id}/step2", follow_redirects=True)
            assert r2.status_code == 200

            # _audit_scan_trigger always writes event_type="scan_triggered";
            # the specific action lives in details["trigger"].
            entries = db_session.exec(
                select(SecurityAuditLog)
                .where(SecurityAuditLog.event_type == "scan_triggered")
                .order_by(SecurityAuditLog.id.desc())
            ).all()
            by_trigger = {}
            for e in entries:
                trigger = (e.details or {}).get("trigger")
                if trigger in ("compliance_wizard_start", "compliance_wizard_step2") and trigger not in by_trigger:
                    by_trigger[trigger] = e

            assert "compliance_wizard_start" in by_trigger
            assert by_trigger["compliance_wizard_start"].tenant_id == test_tenant.id
            assert by_trigger["compliance_wizard_start"].tenant_id is not None

            assert "compliance_wizard_step2" in by_trigger
            assert by_trigger["compliance_wizard_step2"].tenant_id == test_tenant.id
            assert by_trigger["compliance_wizard_step2"].tenant_id is not None
        finally:
            if run:
                db_session.query(ScanResult).filter(ScanResult.target_id == target.id).delete()
                db_session.delete(run)
            db_session.delete(target)
            db_session.commit()


@pytest.mark.compliance_wizard
class TestBrandWatchScanErrorIsolation:
    """run_brand_watch_scan's per-watch loop must isolate failures: one
    watch raising must not abort processing of the remaining watches in the
    same run (or lose their last_run_at update)."""

    def test_one_watch_failure_does_not_abort_others(self, monkeypatch, db_session, test_tenant):
        from yads import worker_tasks
        from yads.models import BrandWatch
        from sqlmodel import select

        failing_watch = BrandWatch(tenant_id=test_tenant.id, keyword="acmecorp-error-isolation-failing")
        ok_watch = BrandWatch(tenant_id=test_tenant.id, keyword="acmecorp-error-isolation-ok")
        db_session.add(failing_watch)
        db_session.add(ok_watch)
        db_session.commit()
        db_session.refresh(failing_watch)
        db_session.refresh(ok_watch)

        def raising_ct_search(keyword):
            if keyword == failing_watch.keyword:
                raise RuntimeError("simulated failure while processing this watch")
            return []

        monkeypatch.setattr(worker_tasks, "_ct_search_keyword", raising_ct_search)
        monkeypatch.setattr(worker_tasks, "_probe_keyword_across_tlds", lambda kw: [])

        try:
            worker_tasks.run_brand_watch_scan()  # must not raise/propagate

            db_session.refresh(failing_watch)
            db_session.refresh(ok_watch)
            assert failing_watch.last_run_at is None, "failing watch's own processing should have rolled back"
            assert ok_watch.last_run_at is not None, "the OTHER watch must still be processed despite the failure"
        finally:
            db_session.delete(failing_watch)
            db_session.delete(ok_watch)
            db_session.commit()
