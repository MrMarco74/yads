"""Wave 6 — API-key-authenticated, tenant-scoped Integrations / Webhooks /
Notifications read surface for yads-mcp. Read-only, and deliberately
secret-redacting: webhook URLs are masked and IntegrationConfig.config
(tokens/credentials) is never returned."""

import pytest


@pytest.fixture
def integrations_fixture(db_session, test_tenant):
    from yads.models import Webhook, ReportSubscription, IntegrationConfig
    from sqlmodel import select, delete

    db_session.exec(delete(Webhook).where(Webhook.tenant_id == test_tenant.id))
    db_session.exec(delete(ReportSubscription).where(ReportSubscription.tenant_id == test_tenant.id))
    db_session.exec(delete(IntegrationConfig).where(IntegrationConfig.tenant_id == test_tenant.id))
    db_session.commit()

    db_session.add(Webhook(
        tenant_id=test_tenant.id,
        url="https://hooks.slack.com/services/T00000/B11111/SECRETTOKEN123456789",
        event_types=["scan_finished", "new_asset"], is_active=True,
    ))
    db_session.add(ReportSubscription(
        tenant_id=test_tenant.id, name="Weekly Exec", report_type="executive_summary",
        recipients=["ciso@example.com"], frequency="weekly", is_active=True,
    ))
    db_session.add(IntegrationConfig(
        tenant_id=test_tenant.id, integration_type="splunk",
        config={"hec_token": "SUPER-SECRET-HEC-TOKEN", "url": "https://splunk:8088"},
        is_active=True,
    ))
    db_session.commit()


def test_integrations_require_api_key(client):
    assert client.get("/api/v1/webhooks").status_code == 401


def test_list_webhooks_masks_secret_url(api_key_client, integrations_fixture):
    r = api_key_client.get("/api/v1/webhooks")
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) >= 1
    wh = items[0]
    assert wh["event_types"] == ["scan_finished", "new_asset"]
    assert wh["is_active"] is True
    # The secret token must NOT appear anywhere in the response
    assert "SECRETTOKEN123456789" not in r.text
    # but the destination host should still be identifiable
    assert "hooks.slack.com" in wh["url_masked"]


def test_list_report_subscriptions(api_key_client, integrations_fixture):
    r = api_key_client.get("/api/v1/report-subscriptions")
    assert r.status_code == 200
    sub = next((s for s in r.json()["items"] if s["name"] == "Weekly Exec"), None)
    assert sub is not None
    assert sub["report_type"] == "executive_summary"
    assert sub["frequency"] == "weekly"
    assert sub["recipients"] == ["ciso@example.com"]


def test_list_integrations_never_leaks_config(api_key_client, integrations_fixture):
    r = api_key_client.get("/api/v1/integrations")
    assert r.status_code == 200
    items = r.json()["items"]
    splunk = next((i for i in items if i["integration_type"] == "splunk"), None)
    assert splunk is not None
    assert splunk["is_active"] is True
    # config (secrets) must never be exposed
    assert "config" not in splunk
    assert "SUPER-SECRET-HEC-TOKEN" not in r.text
