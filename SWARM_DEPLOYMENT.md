# Docker Swarm Deployment Configuration for dmzweb Node

## Overview
This document explains the changes made to ensure that the YADS application deploys to the specific Docker Swarm node `dmzweb` using Portainer endpoint ID `10`.

## Changes Made

### 1. GitLab CI/CD Configuration (`.gitlab-ci.yml`)

**Changed deployment mode from Standalone to Swarm:**
- `PORTAINER_STACK_TYPE`: Changed from `"2"` (Standalone/Compose) to `"1"` (Swarm)
- `COMPOSE_FILE_PATH`: Changed from `docker-compose.prod.yml` to `docker-compose.swarm.yml`

This ensures that Portainer deploys the stack in Swarm mode, which is required for node-specific placement.

### 2. Docker Swarm Configuration (`docker-compose.swarm.yml`)

**Updated all service placement constraints to target `dmzweb` node:**

All services now have the placement constraint:
```yaml
placement:
  constraints:
    - node.hostname == dmzweb
```

This affects the following services:
- `yads-api` - API service
- `yads-worker-primary` - Primary worker
- `yads-worker` - Distributed workers
- `db` - PostgreSQL database
- `redis` - Redis cache
- `yads-scheduler` - Celery beat scheduler

**Added proxy network integration:**
- Added `proxy-net` external network to the networks section
- Connected `yads-api` service to `proxy-net` for reverse proxy access

**Fixed YAML lint error:**
- Removed redundant `encrypted: true` property from network definition (kept in `driver_opts`)

## Deployment Flow

When you push to GitLab, the CI/CD pipeline will:

1. **Build Stage**: Build the Docker image and push to registry
2. **Deploy Stage**: Deploy to Portainer using:
   - Endpoint ID: `10` (from `PORTAINER_ENDPOINT_ID` variable)
   - Stack Type: `1` (Swarm mode)
   - Compose File: `docker-compose.swarm.yml`
   - All services will be constrained to run on node `dmzweb`

## Verification

After deployment, you can verify the node placement with:

```bash
# List all services and their node placement
docker service ls

# Check specific service placement
docker service ps yads_yads-api

# Verify all services are on dmzweb
docker service ps $(docker service ls -q) --filter "desired-state=running" --format "table {{.Name}}\t{{.Node}}\t{{.CurrentState}}"
```

All services should show `dmzweb` in the Node column.

## Prerequisites

Ensure the following are configured:

1. **Docker Swarm is initialized** on your cluster
2. **Node hostname is exactly `dmzweb`** - verify with:
   ```bash
   docker node ls
   ```
3. **Portainer endpoint ID 10** points to your Swarm cluster
4. **CI/CD variable `PORTAINER_ENDPOINT_ID`** is set to `10`
5. **External network `proxy-net`** exists in the Swarm:
   ```bash
   docker network create --driver overlay --attachable proxy-net
   ```

## Network Architecture

- **yads-internal**: Encrypted overlay network for internal service communication
- **yads-frontend**: Overlay network for frontend services
- **proxy-net**: External network for reverse proxy integration (connects to your Nginx reverse proxy)

## Notes

- All services are configured with `mode: replicated` and `replicas: 1`
- The `yads-worker` service can be scaled using the `WORKER_REPLICAS` environment variable
- All workers will still run on `dmzweb` due to the placement constraint
- If you need to distribute workers across multiple nodes in the future, you'll need to modify the placement constraints for the `yads-worker` service
