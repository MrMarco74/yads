# Screenshots für v1.40.0 Release — Checkliste

Alle Screenshots für die Homepage (yads-homepage/*/images/).
Format: PNG, mind. 1280×800px, Dunkel-Theme.

## Login & SSO

- [ ] **login_sso.png** — Login-Seite mit SSO-Button "Mit SSO anmelden (Keycloak)"
  - URL: http://localhost:8085/login
  - AUTH_MODE=oidc muss aktiv sein

- [ ] **keycloak_login.png** — Keycloak Login-Seite nach SSO-Klick
  - URL: http://localhost:8080/realms/frischkorn/protocol/openid-connect/auth?...
  - Zeigt: Realm-Name "YADS – Frischkorn", Benutzername/Passwort-Felder

## Keycloak Admin

- [ ] **keycloak_realms.png** — Keycloak Admin, Realm-Übersicht
  - URL: http://localhost:8080/admin/master/console/#/
  - Zeigt: frischkorn + yads-platform Realms in der Sidebar

- [ ] **keycloak_users.png** — Keycloak User-Liste im frischkorn-Realm
  - URL: http://localhost:8080/admin/master/console/#/frischkorn/users
  - Zeigt: frischkorn-admin, frischkorn-scanner, frischkorn-auditor + yadsadminlocal

- [ ] **keycloak_groups.png** — Keycloak Gruppen mit User-Zuweisung
  - URL: http://localhost:8080/admin/master/console/#/frischkorn/groups
  - Zeigt: frischkorn-admins, frischkorn-scanners, frischkorn-auditors

- [ ] **keycloak_client.png** — YADS Client-Konfiguration
  - URL: http://localhost:8080/admin/master/console/#/frischkorn/clients
  - Zeigt: yads-Client mit Redirect URI + Protocol Mappers

## YADS Dashboard (eingeloggt via SSO)

- [ ] **yads_dashboard_oidc.png** — YADS Dashboard nach SSO-Login
  - URL: http://localhost:8085/
  - Zeigt: Username aus Keycloak in der Topbar, Tenant-Badge "Frischkorn"

## Grafana

- [ ] **grafana_operations.png** — YADS Operations Dashboard
  - URL: http://localhost:3000/d/yads-operations/
  - Zeigt: Alle 7 Panels (Active Scans, Queue, Worker, Error Rate, Log Stream)

- [ ] **grafana_alerts.png** — Alert Rules Übersicht
  - URL: http://localhost:3000/alerting/list
  - Zeigt: 5 provisionierte Regeln (Normal/Pending Status)

- [ ] **grafana_dora.png** — DORA Metriken Dashboard
  - URL: http://localhost:3000/d/yads-dora/
  - Zeigt: Deployment Frequency, Lead Time, MTTR, Change Failure Rate

- [ ] **grafana_loki.png** — Loki Log Explorer
  - URL: http://localhost:3000/explore (Datasource: Loki, Query: {job="yads-api"})
  - Zeigt: YADS API Logs in Echtzeit

## Prometheus

- [ ] **prometheus_metrics.png** — Prometheus Targets + YADS Metriken
  - URL: http://localhost:9090/targets
  - Zeigt: yads-api Target als UP

- [ ] **prometheus_graph.png** — Prometheus Graph einer YADS Metrik
  - URL: http://localhost:9090/graph?g0.expr=yads_queue_depth
  - Zeigt: yads_queue_depth oder yads_active_scans Graph

## MinIO

- [ ] **minio_buckets.png** — MinIO Bucket-Übersicht
  - URL: http://localhost:9001
  - Login: minioadmin / minioadmin123
  - Zeigt: yads-logs-cold + yads-backups Buckets

- [ ] **minio_lifecycle.png** — ILM Policy auf yads-logs-cold
  - URL: http://localhost:9001/buckets/yads-logs-cold/lifecycle
  - Zeigt: 1825 Tage Expiry-Regel

## YADS Audit Log (DORA EU)

- [ ] **audit_log.png** — Security Audit Log mit Hash-Chain
  - URL: http://localhost:8085/audit-log (als admin eingeloggt)
  - Zeigt: Einträge mit entry_hash Spalte (Tamper-Proof)

---

## Verwendung auf der Homepage

Screenshots ablegen in:
- `yads-homepage/de/images/v140/`
- `yads-homepage/en/images/v140/`

Dann in changes.html bei v1.40.0 einbinden:
```html
<img src="./images/v140/grafana_operations.png"
     alt="Grafana YADS Operations Dashboard"
     style="width:100%; border-radius:8px; margin:1rem 0;">
```
