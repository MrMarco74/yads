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

        # Clean up: delete candidate first (child), then watch (parent)
        db_session.query(ShadowDomainCandidate).filter_by(brand_watch_id=watch.id).delete()
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

        r = admin_client.post(f"/compliance-wizard/{run.id}/step2", follow_redirects=True)
        assert r.status_code < 500

        db_session.refresh(run)
        assert run.current_step == 3

        db_session.delete(run)
        db_session.delete(target)
        db_session.commit()


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

        try:
            r = admin_client.post(f"/compliance-wizard/{run.id}/step3", follow_redirects=True)
            assert r.status_code < 500

            db_session.refresh(run)
            assert run.current_step == 4
        finally:
            db_session.delete(run)
            db_session.query(ScanResult).filter_by(target_id=with_server.id).delete()
            db_session.delete(with_server)
            db_session.delete(without_server)
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
                data={"keyword": "musterbank"},
                follow_redirects=True,
            )
            assert r.status_code == 200

            watch = db_session.exec(
                select(BrandWatch).where(BrandWatch.tenant_id == test_tenant.id, BrandWatch.keyword == "musterbank")
            ).first()
            assert watch is not None
            assert watch.active is True
        finally:
            watch = db_session.exec(
                select(BrandWatch).where(BrandWatch.tenant_id == test_tenant.id, BrandWatch.keyword == "musterbank")
            ).first()
            if watch:
                db_session.delete(watch)
            db_session.delete(run)
            db_session.commit()

    def test_step4_nonexistent_run_does_not_create_brand_watch(self, admin_client, test_tenant, db_session):
        from yads.models import BrandWatch
        from sqlmodel import select

        nonexistent_run_id = 999_999

        try:
            r = admin_client.post(
                f"/compliance-wizard/{nonexistent_run_id}/step4",
                data={"keyword": "musterbank-nonexistent-run"},
                follow_redirects=True,
            )
            assert r.status_code == 200

            watch = db_session.exec(
                select(BrandWatch).where(
                    BrandWatch.tenant_id == test_tenant.id,
                    BrandWatch.keyword == "musterbank-nonexistent-run",
                )
            ).first()
            assert watch is None
        finally:
            watch = db_session.exec(
                select(BrandWatch).where(
                    BrandWatch.tenant_id == test_tenant.id,
                    BrandWatch.keyword == "musterbank-nonexistent-run",
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
        from sqlmodel import select

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

        try:
            worker_tasks.run_brand_watch_scan()

            candidates = db_session.exec(
                select(ShadowDomainCandidate).where(ShadowDomainCandidate.brand_watch_id == watch.id)
            ).all()
            discovered = {c.discovered_domain for c in candidates}

            assert "musterbank-shadow.example.net" in discovered
            assert "musterbank.info" in discovered
            assert "musterbank-known.example.com" not in discovered  # already a known Target, not a candidate
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
