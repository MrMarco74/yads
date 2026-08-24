# tests/test_v1_scan_bulk.py
"""Covers bulk-scan-by-criteria preview/submit and bulk-scan-by-selected-ids."""

import pytest


@pytest.fixture
def bulk_targets(db_session, test_tenant):
    from yads.models import Target
    from sqlmodel import select

    domains = ["bulk-fixture-1.example.com", "bulk-fixture-2.example.com"]
    targets = []
    for d in domains:
        existing = db_session.exec(
            select(Target).where(Target.domain == d, Target.tenant_id == test_tenant.id)
        ).first()
        if existing:
            targets.append(existing)
            continue
        t = Target(domain=d, tenant_id=test_tenant.id, tags=[])
        db_session.add(t)
        db_session.commit()
        db_session.refresh(t)
        targets.append(t)
    return targets


def test_bulk_preview_count(api_key_client, bulk_targets):
    r = api_key_client.get("/api/v1/targets/bulk-scan/preview-count")
    assert r.status_code == 200
    assert r.json()["count"] >= 2


def test_bulk_scan_by_criteria(api_key_client, bulk_targets):
    r = api_key_client.post("/api/v1/targets/bulk-scan", json={"scan_types": ["ssl_scanner"]})
    assert r.status_code == 200
    assert r.json()["queued_count"] >= 2


def test_bulk_scan_by_criteria_rejects_no_valid_types(api_key_client, bulk_targets):
    r = api_key_client.post("/api/v1/targets/bulk-scan", json={"scan_types": ["not-a-real-module"]})
    assert r.status_code == 400


def test_bulk_scan_selected(api_key_client, bulk_targets):
    ids = [t.id for t in bulk_targets]
    r = api_key_client.post("/api/v1/targets/bulk/scan", json={"target_ids": ids, "scan_types": ["ssl_scanner"]})
    assert r.status_code == 200
    assert r.json()["queued_count"] == len(ids)
