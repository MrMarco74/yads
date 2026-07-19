# YADS Distributed Worker System

## Overview

The Distributed Worker System enables horizontal scaling of YADS scanning capabilities across multiple machines — no orchestrator (Docker Swarm/Kubernetes) required, just network access between manager and workers. This allows organizations to:

- **Scale scanning capacity** by adding worker nodes
- **Distribute load** across multiple machines
- **Improve resilience** with automatic failover
- **Enforce resource limits** per tenant and globally

## Architecture

```
+------------------------------------------------------------------+
|                         YADS Worker Cluster                       |
+------------------------------------------------------------------+
|  +-------------------+       +--------------------+                |
|  |   Manager Node    |       |  Worker Manager    |                |
|  |  (yads-api)       |<----->|  (yads/core/       |                |
|  |                   |       |   worker_manager)  |                |
|  +-------------------+       +--------------------+                |
|          |                                                         |
|          | Redis (Encrypted Overlay Network)                       |
|          v                                                         |
|  +-------------------+                                             |
|  |   Redis Cluster   |<------+------+------+                       |
|  | (Task Queue +     |       |      |      |                       |
|  |  Log Aggregation) |       |      |      |                       |
|  +-------------------+       |      |      |                       |
|          ^                   |      |      |                       |
|  +-------+-------+   +-------+------+      +-------------+         |
|  |Worker Node 1  |   |Worker Node 2 |      |Worker Node N|         |
|  |(Primary/Local)|   |(Remote)      |      |(Remote)     |         |
|  +---------------+   +--------------+      +-------------+         |
|                                                                    |
|  +-------------------+                                             |
|  |   PostgreSQL      | (Accessed by API + All Workers)             |
|  +-------------------+                                             |
+------------------------------------------------------------------+
```

### Components

| Component | Description |
|-----------|-------------|
| **Manager Node** | Runs the YADS API, PostgreSQL, Redis, and Primary Worker |
| **Primary Worker** | Auto-registered worker on the manager node |
| **Secondary Workers** | Distributed workers running on any machine with network access to the manager |
| **Worker Manager** | Central coordinator for registration, heartbeats, and task routing |
| **Worker Client** | Worker-side component for manager communication |

---

## Quick Start (Single Node)

For testing on a single machine before scaling:

```bash
# 1. Set environment variables
export WORKER_REGISTRATION_TOKEN=$(openssl rand -base64 32)
export POSTGRES_PASSWORD=your_secure_password

# 2. Start with standard compose (includes primary worker)
docker-compose up -d
```

The primary worker automatically registers itself. No additional configuration needed.

---

## Production Deployment (Multi-Host, No Orchestrator)

### Prerequisites

- Docker Engine 24.0+ on the manager host (worker-only hosts just need Python 3.11+, or Docker if you'd rather run the worker image)
- Network connectivity from every worker host to the manager's API port

### Step 1: Bring Up the Manager

```bash
git clone https://github.com/MrMarco74/yads.git && cd yads
cp .env.example .env
# set POSTGRES_PASSWORD and WORKER_REGISTRATION_TOKEN in .env
#   (generate a token with: openssl rand -base64 32)
docker compose up -d --build
```

### Step 2: Add Secondary Workers

On each additional worker host:

```bash
git clone https://github.com/MrMarco74/yads.git && cd yads
pip install -r requirements.txt   # or build+run the yads-worker image instead

WORKER_MODE=secondary \
  MANAGER_URL=http://<MANAGER-IP>:8000 \
  WORKER_REGISTRATION_TOKEN=<same token as Step 1> \
  python scripts/start_distributed_worker.py
```

Each worker self-registers with the manager on startup — no cluster join step, no node labeling.

### Step 3: Scale Workers

Repeat Step 2 on more hosts to add capacity; stop the worker process/container to remove it (it's marked offline after the next missed heartbeat).

---

## Configuration Reference

### Environment Variables

#### Manager Node (yads-api)

| Variable | Default | Description |
|----------|---------|-------------|
| `WORKER_REGISTRATION_TOKEN` | - | Pre-shared token for worker registration (required) |
| `WORKER_MODE` | `primary` | Set to `primary` for manager node |
| `DATABASE_URL` | - | PostgreSQL connection string |
| `REDIS_URL` | - | Redis connection string |

#### Worker Nodes (yads-worker)

| Variable | Default | Description |
|----------|---------|-------------|
| `WORKER_MODE` | `secondary` | Set to `secondary` for distributed workers |
| `MANAGER_URL` | - | URL of the manager API (e.g., `http://yads-api:8000`) |
| `WORKER_REGISTRATION_TOKEN` | - | Token for registration (must match manager) |
| `WORKER_MAX_TASKS` | `4` | Maximum concurrent tasks per worker |
| `WORKER_MAX_NETWORK_MBPS` | `100` | Network bandwidth limit per worker |
| `WORKER_CAPABILITIES` | `all` | Comma-separated list of scan types |

### Global Settings (via UI)

Navigate to **Settings > Distributed Workers** to configure:

| Setting | Description |
|---------|-------------|
| **Registration Token** | View/regenerate the worker registration token |
| **Max Concurrent Scans** | Global limit across all workers |
| **Max Network Throughput** | Global bandwidth limit (Mbit/s) |

---

## Worker Management

### Via Web UI

1. Navigate to **Settings** page
2. Scroll to **Distributed Workers** section
3. View active workers, status, and utilization
4. Use controls to Suspend, Resume, or Drain workers

### Via API

```bash
# List all workers
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/workers/

# Get cluster statistics
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/workers/stats

# Suspend a worker
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/workers/{node_id}/suspend

# Resume a worker
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/workers/{node_id}/resume

# Drain a worker (finish current tasks, then stop)
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/workers/{node_id}/drain

# Remove a worker
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/workers/{node_id}
```

### Worker States

| State | Description |
|-------|-------------|
| `pending` | Registered but not yet active |
| `active` | Running and accepting tasks |
| `suspended` | Manually paused, not accepting new tasks |
| `draining` | Finishing current tasks before going offline |
| `offline` | Not responding (missed heartbeats) |

---

## Resource Quotas

### Hierarchy

Resource limits are enforced at three levels:

1. **Global Limits** - Apply to entire cluster
2. **Per-Worker Limits** - Apply to individual workers
3. **Per-Tenant Limits** - Apply to specific tenants

### Configuring Quotas

#### Global Quota (via API)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"max_concurrent_scans": 50, "max_daily_scans": 5000}' \
  http://localhost:8000/api/workers/quotas/global
```

#### Tenant Quota (via API)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"max_concurrent_scans": 10, "max_daily_scans": 500}' \
  http://localhost:8000/api/workers/quotas/tenant/{tenant_id}
```

#### Reset Daily Counters

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/workers/quotas/reset-daily
```

---

## Unified Logging

The distributed system aggregates logs from all workers into a unified view.

### Accessing Unified Logs

1. Navigate to **Settings > Distributed Workers**
2. Click **View Unified Scan Logs**
3. Or access directly: `/workers/logs`

### Log Filtering

- **By Tenant**: Filter logs to specific tenant
- **By Worker**: Filter logs from specific worker node
- **By Level**: Filter by INFO, WARNING, ERROR

### Log Retention

- Per-target logs: 200 entries, 1-hour TTL
- Tenant aggregate logs: 1000 entries, 2-hour TTL
- Worker debug logs: 500 entries, 1-hour TTL
- Unified stream: 5000 entries, 1-hour TTL

### Via API

```bash
# Get unified logs
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/workers/logs/unified?limit=100"

# Filter by tenant
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/workers/logs/unified?tenant_id=1&limit=100"

# Filter by worker
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/workers/logs/unified?worker_id=worker-node1-abc123&limit=100"

# Get tenant-specific logs
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/workers/logs/tenant/1?limit=100"
```

---

## Health Monitoring

### Heartbeat System

- Workers send heartbeats every **30 seconds**
- Workers marked offline after **180 seconds** (3 missed heartbeats)
- Offline workers' tasks are automatically requeued

### Manual Health Check

Trigger a manual health check:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/workers/health-check
```

Response:
```json
{
  "workers_marked_offline": 0,
  "tasks_requeued": 0
}
```

### Monitoring Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/workers/` | List all workers with status |
| `GET /api/workers/stats` | Cluster-wide statistics |
| `GET /api/workers/{node_id}` | Specific worker details |

---

## Task Routing

### Load Balancing Algorithm

1. Check tenant quota is not exceeded
2. Get active workers with capacity (load < 80%)
3. Filter by capability (scan types the worker supports)
4. Sort by load (least-loaded first)
5. Assign task to best available worker

### Task Assignment

When a scan is queued:
1. Worker Manager selects the best worker
2. Task is assigned to worker
3. Worker reports task started
4. Worker executes scan modules
5. Worker reports task completed
6. Quotas are updated

---

## Failure Handling

### Worker Goes Offline

1. Heartbeat timeout detected (180s)
2. Worker marked as `offline`
3. Running tasks on that worker are requeued
4. Target status reset to allow retry
5. Tasks assigned to other available workers

### Manager Failure

- Workers continue executing current tasks
- New tasks queue in Redis
- Workers retry registration when manager returns
- No data loss due to Redis persistence

### Mid-Scan Failure

1. Task revoked
2. Target status reset to `idle`
3. Partial results preserved (already saved modules)
4. Task can be manually restarted

---

## Security

### Network Security

- Docker overlay network with **IPSec encryption**
- Workers communicate only via internal network
- Only API port (8000) exposed externally

### Authentication

- **Registration Token**: Pre-shared secret for worker enrollment
- **Worker JWT**: Short-lived tokens (1h) for API calls, refreshed via heartbeat
- Primary worker uses database-direct access (no HTTP auth needed)

### Tenant Isolation

- All logs tagged with `tenant_id`
- API enforces tenant filtering for non-admins
- Resource quotas isolated per tenant

---

## Troubleshooting

### Worker Not Registering

```bash
# Check worker logs
docker service logs yads_yads-worker

# Verify registration token matches
echo $WORKER_REGISTRATION_TOKEN

# Check network connectivity
docker exec -it <worker_container> curl http://yads-api:8000/docs
```

### Workers Going Offline

```bash
# Check heartbeat interval
docker service logs yads_yads-worker | grep heartbeat

# Check Redis connectivity
docker exec -it <worker_container> redis-cli -u $REDIS_URL ping
```

### Tasks Not Distributing

```bash
# Check worker capacity
curl http://localhost:8000/api/workers/stats

# Check quota limits
curl http://localhost:8000/api/workers/quotas

# Verify worker capabilities
curl http://localhost:8000/api/workers/
```

### High Memory Usage

```bash
# Check Redis memory
docker exec yads-redis redis-cli INFO memory

# Clear old logs
docker exec yads-redis redis-cli FLUSHDB  # CAUTION: Clears all Redis data
```

---

## Best Practices

### Sizing Workers

| Scan Volume | Workers | Max Tasks/Worker | Total Capacity |
|-------------|---------|------------------|----------------|
| Small (<100/day) | 1-2 | 4 | 4-8 concurrent |
| Medium (100-500/day) | 3-5 | 4 | 12-20 concurrent |
| Large (500+/day) | 5-10 | 4-8 | 20-80 concurrent |

### Resource Allocation

```yaml
# Recommended per worker
resources:
  limits:
    memory: 4G
    cpus: '2'
  reservations:
    memory: 1G
    cpus: '0.5'
```

### Monitoring Recommendations

1. Monitor worker heartbeat latency
2. Track task queue depth
3. Alert on workers going offline
4. Monitor quota utilization
5. Check unified logs for errors regularly

---

## Migration from Single Worker

To migrate an existing single-worker deployment to distributed mode:

1. **Backup Data**
   ```bash
   docker exec yads-api /app/scripts/backup_db.sh
   ```

2. **Configure Environment**
   - Add `WORKER_REGISTRATION_TOKEN` to `.env`
   - Set `WORKER_MODE=primary` for the manager

3. **Restart the Manager**
   ```bash
   docker compose up -d --build
   ```

4. **Add Worker Hosts**
   - On each additional machine, run `scripts/start_distributed_worker.py` with
     `WORKER_MODE=secondary` and `MANAGER_URL` pointed at the manager
     (see [Step 2](#step-2-add-secondary-workers) above) — each one
     self-registers, no cluster join needed

---

## API Reference

### Worker Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/workers/register` | Register new worker |
| POST | `/api/workers/{node_id}/heartbeat` | Send heartbeat |
| GET | `/api/workers/` | List workers (HTML/JSON) |
| GET | `/api/workers/stats` | Cluster statistics |
| GET | `/api/workers/{node_id}` | Worker details |
| POST | `/api/workers/{node_id}/suspend` | Suspend worker |
| POST | `/api/workers/{node_id}/resume` | Resume worker |
| POST | `/api/workers/{node_id}/drain` | Drain worker |
| DELETE | `/api/workers/{node_id}` | Remove worker |

### Token Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/workers/token/current` | Get masked token |
| POST | `/api/workers/token/regenerate` | Generate new token |

### Log Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/workers/logs/unified` | Unified logs with filtering |
| GET | `/api/workers/logs/tenant/{id}` | Tenant-specific logs |
| GET | `/api/workers/logs/worker/{id}` | Worker-specific logs |

### Quota Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/workers/quotas` | List all quotas |
| POST | `/api/workers/quotas/global` | Set global quota |
| POST | `/api/workers/quotas/tenant/{id}` | Set tenant quota |
| POST | `/api/workers/quotas/reset-daily` | Reset daily counters |
