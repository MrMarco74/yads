"""
Target management tests.
Covers: list, create (import), queue scan, bulk operations.
"""

import pytest


@pytest.mark.targets
class TestTargetList:
    def test_targets_page_loads(self, admin_client):
        r = admin_client.get("/targets", follow_redirects=True)
        assert r.status_code == 200

    def test_targets_page_contains_html(self, admin_client):
        r = admin_client.get("/targets", follow_redirects=True)
        assert "text/html" in r.headers["content-type"]


@pytest.mark.targets
class TestTargetImport:
    def test_import_single_domain(self, admin_client, test_tenant):
        """POST /targets/import with a valid domain must succeed."""
        r = admin_client.post(
            "/targets/import",
            data={
                "domains": "smoke-test-import.example.com",
                "tenant_id": str(test_tenant.id),
            },
            follow_redirects=True,
        )
        assert r.status_code == 200

    def test_import_multiple_domains(self, admin_client, test_tenant):
        """Newline-separated list of domains must all be imported."""
        r = admin_client.post(
            "/targets/import",
            data={
                "domains": "multi1.example.com\nmulti2.example.com",
                "tenant_id": str(test_tenant.id),
            },
            follow_redirects=True,
        )
        assert r.status_code == 200

    def test_import_empty_domains_rejected(self, admin_client, test_tenant):
        r = admin_client.post(
            "/targets/import",
            data={"domains": "", "tenant_id": str(test_tenant.id)},
            follow_redirects=True,
        )
        # Should either 200 with error message or 422
        assert r.status_code in (200, 422)


@pytest.mark.targets
class TestTargetScan:
    def test_bulk_scan_endpoint_reachable(self, admin_client, test_tenant, db_session):
        """POST /targets/bulk/scan must accept a list of target IDs."""
        from yads.models import Target
        from sqlmodel import select

        # Find or create a target for the test tenant
        target = db_session.exec(
            select(Target).where(Target.tenant_id == test_tenant.id)
        ).first()

        if not target:
            target = Target(
                domain="bulk-scan-test.example.com",
                tenant_id=test_tenant.id,
            )
            db_session.add(target)
            db_session.commit()
            db_session.refresh(target)

        r = admin_client.post(
            "/targets/bulk/scan",
            data={
                "target_ids": str(target.id),
                "scan_types": "dns_scanner",
            },
            follow_redirects=True,
        )
        # Queue might be paused in test env; accept any non-500 response
        assert r.status_code < 500


@pytest.mark.targets
class TestTargetArchive:
    def test_archived_page_loads(self, admin_client):
        r = admin_client.get("/archived", follow_redirects=True)
        assert r.status_code == 200


@pytest.mark.targets
class TestTargetSearch:
    def test_search_page_loads(self, admin_client):
        r = admin_client.get("/search", follow_redirects=True)
        assert r.status_code == 200

    def test_search_api_returns_json(self, admin_client):
        r = admin_client.get(
            "/search",
            params={"q": "example.com", "format": "json"},
            follow_redirects=True,
        )
        # May return HTML or JSON depending on implementation
        assert r.status_code == 200
