# Distributed Workers - Quick Start Guide

This guide provides step-by-step instructions to set up distributed workers for YADS.

## Prerequisites

- Docker Engine 24.0+ (or just Python 3.11+ on worker-only machines)
- At least 2 machines (1 manager, 1+ workers)
- Network connectivity between machines

---

## Step 1: Prepare the Manager Node

On the machine that will be the manager (runs API, worker, database, Redis):

```bash
# 1. Clone and configure
git clone https://github.com/MrMarco74/yads.git && cd yads
cp .env.example .env

# 2. Generate secure tokens
export POSTGRES_PASSWORD=$(openssl rand -base64 24)
export WORKER_REGISTRATION_TOKEN=$(openssl rand -base64 32)

# 3. Add both to .env, then bring up the manager stack (builds from source)
echo "POSTGRES_PASSWORD=${POSTGRES_PASSWORD}" >> .env
echo "WORKER_REGISTRATION_TOKEN=${WORKER_REGISTRATION_TOKEN}" >> .env
docker compose up -d --build
```

---

## Step 2: Add Secondary Workers

On each additional worker machine — no cluster join, no orchestrator required, just network access to the manager's API port:

```bash
git clone https://github.com/MrMarco74/yads.git && cd yads
pip install -r requirements.txt   # or build the yads-worker image and `docker run` it

WORKER_MODE=secondary \
  MANAGER_URL=http://<MANAGER_IP>:8000 \
  WORKER_REGISTRATION_TOKEN=<same token as Step 1> \
  python scripts/start_distributed_worker.py
```

Repeat on as many worker machines as you need.

---

## Step 3: Access the Web UI

1. Open `http://<MANAGER_IP>:8000` in your browser
2. Login with default credentials: `admin` / `admin`
3. **Change the password immediately!**
4. Navigate to **Settings** to see the Distributed Workers section

---

## Step 4: Verify Workers

In the Settings page, scroll to "Distributed Workers":

- You should see the primary worker and any secondary workers
- Status should show "active" with green indicator
- Check cluster statistics for total capacity

Or via API:
```bash
# Get auth token first (login via UI or API)
curl -X POST http://<MANAGER_IP>:8000/api/auth/token \
  -d "username=admin&password=admin"

# List workers
curl -H "Authorization: Bearer <TOKEN>" \
  http://<MANAGER_IP>:8000/api/workers/
```

---

## Step 5: Scale Workers

Just repeat Step 2 on another machine — each secondary worker registers itself with the manager on startup. To scale down, stop the worker process/container; it will be marked offline after the next missed heartbeat.

---

## Common Operations

### View Worker Logs
Each worker logs to its own stdout — `docker compose logs -f yads-worker` on the manager, or check the process output on secondary worker hosts. The aggregated view is also available at `/workers/logs` in the UI (see below).

### Suspend a Worker
```bash
curl -X POST -H "Authorization: Bearer <TOKEN>" \
  http://<MANAGER_IP>:8000/api/workers/<node_id>/suspend
```

### View Unified Logs
Open `http://<MANAGER_IP>:8000/workers/logs` in your browser.

### Regenerate Registration Token
1. Go to Settings > Distributed Workers
2. Click "Regenerate" next to Registration Token
3. Restart worker services to re-register

---

## Troubleshooting

### Workers Not Appearing

1. Check the worker's own logs/stdout
2. Verify network connectivity to manager
3. Ensure registration token matches

### Workers Going Offline

1. Check heartbeat in logs
2. Verify Redis connectivity
3. Increase `WORKER_MAX_TASKS` if overloaded

### Tasks Not Distributing

1. Check quota limits in Settings
2. Verify workers have capacity (< 80% load)
3. Check worker capabilities match scan types

---

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `POSTGRES_PASSWORD` | Yes | - | Database password |
| `WORKER_REGISTRATION_TOKEN` | Yes | - | Token for worker auth |
| `WORKER_MODE` | Yes (workers) | `standalone` | `primary`, `secondary`, or `standalone` |
| `MANAGER_URL` | Yes (secondary workers) | - | URL of the manager API |
| `WORKER_MAX_TASKS` | No | `4` | Tasks per worker |
| `MFA_ENABLED` | No | `true` | Require MFA |

---

## Next Steps

- Configure resource quotas per tenant
- Set up monitoring and alerting
- Review the full documentation: [DISTRIBUTED_WORKERS.md](DISTRIBUTED_WORKERS.md)
