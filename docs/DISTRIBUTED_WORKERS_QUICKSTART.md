# Distributed Workers - Quick Start Guide

This guide provides step-by-step instructions to set up distributed workers for YADS.

## Prerequisites

- Docker Engine 24.0+
- At least 2 machines (1 manager, 1+ workers)
- Network connectivity between machines
- YADS container image available

---

## Step 1: Prepare the Manager Node

On the machine that will be the manager (runs API, database, Redis):

```bash
# 1. Create project directory
mkdir -p /opt/yads && cd /opt/yads

# 2. Generate secure tokens
export POSTGRES_PASSWORD=$(openssl rand -base64 24)
export WORKER_REGISTRATION_TOKEN=$(openssl rand -base64 32)

# 3. Save to .env file
cat > .env << EOF
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
WORKER_REGISTRATION_TOKEN=${WORKER_REGISTRATION_TOKEN}
YADS_IMAGE=registry.example.com/yads/yads:latest
WORKER_REPLICAS=2
EOF

# 4. Initialize Docker Swarm
docker swarm init --advertise-addr <MANAGER_IP>

# 5. Save the worker join command (you'll need this later)
docker swarm join-token worker
```

---

## Step 2: Join Worker Nodes to Swarm

On each worker machine:

```bash
# Run the join command from Step 1
docker swarm join --token <TOKEN> <MANAGER_IP>:2377
```

---

## Step 3: Label Worker Nodes

Back on the manager node:

```bash
# List all nodes
docker node ls

# Label each worker node
docker node update --label-add yads-worker=true <WORKER_NODE_NAME>
```

---

## Step 4: Deploy the Stack

On the manager node:

```bash
# Download the swarm compose file (or copy from repo)
curl -O https://raw.githubusercontent.com/your-org/yads/main/docker-compose.swarm.yml

# Deploy
docker stack deploy -c docker-compose.swarm.yml yads

# Verify all services are running
docker stack services yads
```

Expected output:
```
ID             NAME                   MODE         REPLICAS   IMAGE
abc123         yads_yads-api          replicated   1/1        yads:latest
def456         yads_yads-worker       replicated   2/2        yads:latest
ghi789         yads_yads-worker-primary replicated 1/1        yads:latest
jkl012         yads_db                replicated   1/1        postgres:15-alpine
mno345         yads_redis             replicated   1/1        redis:7-alpine
```

---

## Step 5: Access the Web UI

1. Open `http://<MANAGER_IP>:8000` in your browser
2. Login with default credentials: `admin` / `admin`
3. **Change the password immediately!**
4. Navigate to **Settings** to see the Distributed Workers section

---

## Step 6: Verify Workers

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

## Step 7: Scale Workers

```bash
# Add more workers
docker service scale yads_yads-worker=5

# Check distribution
docker service ps yads_yads-worker
```

---

## Common Operations

### View Worker Logs
```bash
docker service logs yads_yads-worker -f
```

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

1. Check worker logs: `docker service logs yads_yads-worker`
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
| `YADS_IMAGE` | No | `yads:latest` | Container image |
| `WORKER_REPLICAS` | No | `2` | Initial worker count |
| `WORKER_MAX_TASKS` | No | `4` | Tasks per worker |
| `MFA_ENABLED` | No | `true` | Require MFA |

---

## Next Steps

- Configure resource quotas per tenant
- Set up monitoring and alerting
- Review the full documentation: [DISTRIBUTED_WORKERS.md](DISTRIBUTED_WORKERS.md)
