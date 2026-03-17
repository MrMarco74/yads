# YADS Observability & Infrastructure Stack

## Services and Ports

| Service        | Port(s)       | Description                              |
|----------------|---------------|------------------------------------------|
| Keycloak       | 8080          | Identity Provider (SSO/OIDC)             |
| Prometheus     | 9090          | Metrics collection & alerting rules      |
| Grafana        | 3000          | Dashboards, alerting, visualization      |
| Loki           | 3100          | Log aggregation (30d hot retention)      |
| Promtail       | 9080          | Log shipper (reads YADS log files)       |
| MinIO          | 9000 (API)    | S3-compatible cold log storage (5 years) |
| MinIO Console  | 9001          | MinIO web UI                             |

## Logins

### Grafana
- URL: http://localhost:3000
- User: `admin`
- Password: `admin`

### Keycloak
- URL: http://localhost:8080
- User: `admin`
- Password: `admin`
- Realm import directory: `keycloak/realms/`

### MinIO Console
- URL: http://localhost:9001
- User: `minioadmin`
- Password: `minioadmin123`

## Log Retention

- **Hot storage (Loki/filesystem):** 30 days
- **Cold storage (MinIO `yads-logs-cold`):** 5 years (1825 days ILM policy)

Run `monitoring/minio/init-buckets.sh` inside the MinIO container (or via `mc`) to create the bucket with the retention policy.

## Alerting

Grafana is pre-configured with two notification channels:
- **Microsoft Teams:** set your webhook URL in `monitoring/grafana/provisioning/alerting/teams-email.yml`
- **Email:** `yads-alerts@example.com` (configure SMTP in Grafana environment variables)

Alert rules are defined in `monitoring/grafana/provisioning/alerting/alert-rules.yml`:
- Worker task crash rate > 10% (5 min window) — **critical**
- Queue paused > 10 minutes — **warning**
- No active Celery workers — **critical**
- Scan failure rate > 20% (10 min window) — **warning**

## Quick Start

```bash
# Start full stack including observability
docker-compose up -d

# Init MinIO cold-storage bucket (first run only)
docker-compose exec minio sh /docker-entrypoint-initdb.d/init-buckets.sh
```
