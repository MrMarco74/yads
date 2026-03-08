#!/usr/bin/env python3
"""
Screenshot-Capture für YADS v1.40 Release.
Erfasst alle Screenshots aus der Checkliste release_assets/screenshots_v1.40_checklist.md
"""

from playwright.sync_api import sync_playwright
import time
import os

YADS_URL = "http://localhost:8085"
KC_URL    = "http://localhost:8080"
GRAFANA   = "http://localhost:3000"
PROM_URL  = "http://localhost:9090"
MINIO_URL = "http://localhost:9001"

YADS_OIDC_USER = "frischkorn-scanner"
YADS_OIDC_PASS = "Scanner1234!"
KC_ADMIN_USER  = "admin"
KC_ADMIN_PASS  = "admin"
GRAFANA_USER   = "admin"
GRAFANA_PASS   = "admin"
MINIO_USER     = "minioadmin"
MINIO_PASS     = "minioadmin123"

OUT = os.path.join(os.path.dirname(__file__), "..", "yads-homepage", "de", "images", "v140")
os.makedirs(OUT, exist_ok=True)

def shot(page, name, wait=1.5):
    time.sleep(wait)
    path = os.path.join(OUT, name)
    page.screenshot(path=path, full_page=False)
    print(f"  ✓ {name}")
    return path


def run():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(viewport={"width": 1440, "height": 900})
        page = ctx.new_page()

        # ----------------------------------------------------------------
        # 1. YADS Login-Seite mit SSO-Button
        # ----------------------------------------------------------------
        print("\n[1/6] YADS Login & SSO...")
        page.goto(f"{YADS_URL}/login")
        page.wait_for_load_state("networkidle")
        shot(page, "login_sso.png")

        # ----------------------------------------------------------------
        # 2. Keycloak Login-Seite (nach SSO-Klick)
        # ----------------------------------------------------------------
        print("\n[2/6] Keycloak Login...")
        page.goto(f"{KC_URL}/realms/frischkorn/protocol/openid-connect/auth"
                  f"?client_id=yads&redirect_uri={YADS_URL}/auth/oidc/callback"
                  f"&response_type=code&scope=openid+profile+email")
        page.wait_for_load_state("networkidle")
        shot(page, "keycloak_login.png")

        # ----------------------------------------------------------------
        # 3. Keycloak Admin Console
        # ----------------------------------------------------------------
        print("\n[3/6] Keycloak Admin...")

        # Admin Login
        page.goto(f"{KC_URL}/admin/master/console/")
        page.wait_for_load_state("networkidle")
        time.sleep(2)
        try:
            page.fill('input[id="username"]', KC_ADMIN_USER)
            page.fill('input[id="password"]', KC_ADMIN_PASS)
            page.click('input[id="kc-login"]')
            page.wait_for_load_state("networkidle")
            time.sleep(3)
        except Exception as e:
            print(f"  [WARN] Admin login: {e}")

        # Realm-Übersicht (Master mit Realm-Liste)
        page.goto(f"{KC_URL}/admin/master/console/#/")
        time.sleep(3)
        shot(page, "keycloak_realms.png", wait=2)

        # Users im frischkorn-Realm
        page.goto(f"{KC_URL}/admin/master/console/#/frischkorn/users")
        time.sleep(3)
        shot(page, "keycloak_users.png", wait=2)

        # Gruppen im frischkorn-Realm
        page.goto(f"{KC_URL}/admin/master/console/#/frischkorn/groups")
        time.sleep(3)
        shot(page, "keycloak_groups.png", wait=2)

        # Client-Konfiguration
        page.goto(f"{KC_URL}/admin/master/console/#/frischkorn/clients")
        time.sleep(3)
        shot(page, "keycloak_client.png", wait=2)

        # ----------------------------------------------------------------
        # 4. YADS Dashboard via OIDC (vollständiger Login-Flow)
        # ----------------------------------------------------------------
        print("\n[4/6] YADS OIDC Login...")

        # Neuer Context ohne gespeicherte Session
        ctx2 = browser.new_context(viewport={"width": 1440, "height": 900})
        page2 = ctx2.new_page()

        page2.goto(f"{YADS_URL}/auth/oidc/login")
        page2.wait_for_load_state("networkidle")
        time.sleep(2)

        try:
            page2.fill('input[id="username"]', YADS_OIDC_USER)
            page2.fill('input[id="password"]', YADS_OIDC_PASS)
            page2.click('input[id="kc-login"]')
            page2.wait_for_url(f"{YADS_URL}/**", timeout=15000)
            page2.wait_for_load_state("networkidle")
            time.sleep(2)
            shot(page2, "yads_dashboard_oidc.png")
        except Exception as e:
            print(f"  [WARN] YADS OIDC login: {e}")
            page2.screenshot(path=os.path.join(OUT, "yads_dashboard_oidc_error.png"))

        ctx2.close()

        # ----------------------------------------------------------------
        # 5. Grafana
        # ----------------------------------------------------------------
        print("\n[5/6] Grafana...")
        ctx3 = browser.new_context(viewport={"width": 1440, "height": 900})
        page3 = ctx3.new_page()

        # Login
        page3.goto(f"{GRAFANA}/login")
        page3.wait_for_load_state("networkidle")
        time.sleep(1)
        try:
            page3.fill('input[name="user"]', GRAFANA_USER)
            page3.fill('input[name="password"]', GRAFANA_PASS)
            page3.click('button[type="submit"]')
            page3.wait_for_load_state("networkidle")
            time.sleep(2)
            # Skip "change password" prompt if shown
            try:
                page3.click('button:has-text("Skip")', timeout=3000)
                time.sleep(1)
            except:
                pass
        except Exception as e:
            print(f"  [WARN] Grafana login: {e}")

        # Operations Dashboard
        page3.goto(f"{GRAFANA}/dashboards")
        time.sleep(2)
        shot(page3, "grafana_dashboards.png")

        # Direkt zu YADS Operations Dashboard
        page3.goto(f"{GRAFANA}/d/yads-operations/yads-operations")
        time.sleep(4)
        shot(page3, "grafana_operations.png", wait=2)

        # DORA Dashboard
        page3.goto(f"{GRAFANA}/d/yads-dora/yads-dora")
        time.sleep(4)
        shot(page3, "grafana_dora.png", wait=2)

        # Alert Rules
        page3.goto(f"{GRAFANA}/alerting/list")
        time.sleep(2)
        shot(page3, "grafana_alerts.png")

        # Loki Explore
        page3.goto(f"{GRAFANA}/explore?left=%7B%22datasource%22:%22Loki%22%7D")
        time.sleep(3)
        shot(page3, "grafana_loki.png")

        ctx3.close()

        # ----------------------------------------------------------------
        # 6. Prometheus + MinIO
        # ----------------------------------------------------------------
        print("\n[6/6] Prometheus + MinIO...")
        ctx4 = browser.new_context(viewport={"width": 1440, "height": 900})
        page4 = ctx4.new_page()

        # Prometheus Targets
        page4.goto(f"{PROM_URL}/targets")
        time.sleep(2)
        shot(page4, "prometheus_metrics.png")

        # Prometheus Graph
        page4.goto(f"{PROM_URL}/graph?g0.expr=yads_queue_depth&g0.tab=0")
        time.sleep(3)
        shot(page4, "prometheus_graph.png")

        # MinIO Login
        page4.goto(f"{MINIO_URL}/login")
        time.sleep(1)
        try:
            page4.fill('input[id="accessKey"]', MINIO_USER)
            page4.fill('input[id="secretKey"]', MINIO_PASS)
            page4.click('button[type="submit"]')
            page4.wait_for_load_state("networkidle")
            time.sleep(2)
        except Exception as e:
            print(f"  [WARN] MinIO login: {e}")

        page4.goto(f"{MINIO_URL}/buckets")
        time.sleep(2)
        shot(page4, "minio_buckets.png")

        page4.goto(f"{MINIO_URL}/buckets/yads-logs-cold/admin/lifecycle")
        time.sleep(2)
        shot(page4, "minio_lifecycle.png")

        ctx4.close()
        browser.close()

    print(f"\n{'='*50}")
    print(f"Screenshots gespeichert in: {OUT}")
    files = sorted(os.listdir(OUT))
    for f in files:
        size = os.path.getsize(os.path.join(OUT, f))
        print(f"  {f:40s} {size//1024:>5} KB")
    print(f"{'='*50}")


if __name__ == "__main__":
    run()
