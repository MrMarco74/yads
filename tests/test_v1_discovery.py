"""Wave 5 — API-key-authenticated, tenant-scoped OSINT / Discovery /
Intelligence read surface for yads-mcp: discovery sessions and their
candidates, brand watches, and shadow-domain candidates (the DORA
shadow-domain hunt output)."""

import pytest


@pytest.fixture
def discovery_fixture(db_session, test_tenant):
    from yads.models import (DiscoverySession, DiscoveryCandidate,
                             BrandWatch, ShadowDomainCandidate)
    from sqlmodel import select, delete

    # Clean prior fixture rows for determinism
    sess = db_session.exec(
        select(DiscoverySession).where(DiscoverySession.name == "wave5-fixture-session",
                                       DiscoverySession.tenant_id == test_tenant.id)
    ).first()
    if not sess:
        sess = DiscoverySession(tenant_id=test_tenant.id, name="wave5-fixture-session",
                                seed_domains=["examplecorp.de"], status="completed",
                                total_discovered=2)
        db_session.add(sess); db_session.commit(); db_session.refresh(sess)

    db_session.exec(delete(DiscoveryCandidate).where(DiscoveryCandidate.session_id == sess.id))
    db_session.commit()
    for dom, score, status in [("shadow1.examplecorp.uk", 0.9, "pending"),
                               ("shadow2.examplecorp.uk", 0.5, "accepted")]:
        db_session.add(DiscoveryCandidate(
            session_id=sess.id, domain=dom, source_scanner="dns_scanner",
            relevance_score=score, status=status, matching_signals=["brand"],
        ))

    bw = db_session.exec(
        select(BrandWatch).where(BrandWatch.keyword == "wave5brand",
                                 BrandWatch.tenant_id == test_tenant.id)
    ).first()
    if not bw:
        bw = BrandWatch(tenant_id=test_tenant.id, keyword="wave5brand", active=True)
        db_session.add(bw); db_session.commit(); db_session.refresh(bw)

    db_session.exec(delete(ShadowDomainCandidate).where(ShadowDomainCandidate.brand_watch_id == bw.id))
    db_session.commit()
    for dom, status in [("wave5brand-login.com", "new"), ("wave5brand-pay.net", "confirmed")]:
        db_session.add(ShadowDomainCandidate(
            brand_watch_id=bw.id, tenant_id=test_tenant.id,
            discovered_domain=dom, source="ct_log", status=status,
        ))
    db_session.commit()
    return {"session_id": sess.id, "brand_watch_id": bw.id}


def test_discovery_requires_api_key(client):
    assert client.get("/api/v1/discovery/sessions").status_code == 401


def test_list_discovery_sessions(api_key_client, discovery_fixture):
    r = api_key_client.get("/api/v1/discovery/sessions")
    assert r.status_code == 200
    names = {s["name"] for s in r.json()["items"]}
    assert "wave5-fixture-session" in names


def test_get_discovery_session(api_key_client, discovery_fixture):
    sid = discovery_fixture["session_id"]
    r = api_key_client.get(f"/api/v1/discovery/sessions/{sid}")
    assert r.status_code == 200
    assert r.json()["name"] == "wave5-fixture-session"


def test_get_discovery_session_unknown_404(api_key_client, discovery_fixture):
    assert api_key_client.get("/api/v1/discovery/sessions/99999999").status_code == 404


def test_list_discovery_candidates(api_key_client, discovery_fixture):
    sid = discovery_fixture["session_id"]
    r = api_key_client.get(f"/api/v1/discovery/sessions/{sid}/candidates")
    assert r.status_code == 200
    domains = {c["domain"] for c in r.json()["items"]}
    assert {"shadow1.examplecorp.uk", "shadow2.examplecorp.uk"} <= domains


def test_list_discovery_candidates_filter_status(api_key_client, discovery_fixture):
    sid = discovery_fixture["session_id"]
    r = api_key_client.get(f"/api/v1/discovery/sessions/{sid}/candidates?status=accepted")
    assert all(c["status"] == "accepted" for c in r.json()["items"])


def test_list_brand_watches(api_key_client, discovery_fixture):
    r = api_key_client.get("/api/v1/brand-watches")
    assert r.status_code == 200
    bw = next((x for x in r.json()["items"] if x["keyword"] == "wave5brand"), None)
    assert bw is not None
    assert bw["candidate_count"] >= 2


def test_list_shadow_domains(api_key_client, discovery_fixture):
    r = api_key_client.get("/api/v1/shadow-domains")
    assert r.status_code == 200
    domains = {s["discovered_domain"] for s in r.json()["items"]}
    assert {"wave5brand-login.com", "wave5brand-pay.net"} <= domains


def test_list_shadow_domains_filter_status(api_key_client, discovery_fixture):
    r = api_key_client.get("/api/v1/shadow-domains?status=confirmed")
    assert all(s["status"] == "confirmed" for s in r.json()["items"])
