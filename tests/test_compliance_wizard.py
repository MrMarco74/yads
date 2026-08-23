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
