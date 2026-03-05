#!/bin/bash
set -e

# ==============================================================================
# Configuration
# ==============================================================================
REMOTE_HOST="root@prod.example.com"
STACK_NAME="yads"
IMAGE_NAME="yads:latest"
REMOTE_DEPLOY_DIR="~/deploy/yads"
DOCKER_COMPOSE_FILE="docker-compose.swarm.yml"
IMAGE_ARCHIVE="yads_deploy.tgz"
# The image name expected by the swarm stack (must match docker-compose.swarm.yml)
REGISTRY_IMAGE="gitlab.example.internal:5050/apps/yads/yads:latest"
# Backup container
BACKUP_IMAGE_NAME="yads-backup:latest"
BACKUP_REGISTRY_IMAGE="gitlab.example.internal:5050/apps/yads/yads-backup:latest"
BACKUP_IMAGE_ARCHIVE="yads_backup_deploy.tgz"
# List of services to force update (space-separated)
SERVICES_TO_UPDATE="${STACK_NAME}_yads-api ${STACK_NAME}_yads-worker ${STACK_NAME}_yads-worker-primary ${STACK_NAME}_yads-backup"
# Docker volumes that hold persistent data
DATA_VOLUMES="${STACK_NAME}_postgres_data ${STACK_NAME}_redis_data ${STACK_NAME}_logs ${STACK_NAME}_data ${STACK_NAME}_nuclei_templates"

# ==============================================================================
# Mode Selection
# ==============================================================================
echo "=============================================================================="
echo "YADS DEPLOYMENT"
echo "=============================================================================="
echo "Remote Host:    $REMOTE_HOST"
echo "Stack Name:     $STACK_NAME"
echo "Image Name:     $IMAGE_NAME"
echo "Compose File:   $DOCKER_COMPOSE_FILE"
echo "=============================================================================="
echo ""
echo "What would you like to do?"
echo "  1) Update — deploy new image, keep all data"
echo "  2) Fresh install — wipe everything and start from scratch"
echo ""
read -p "Choose [1/2]: " CHOICE

case "$CHOICE" in
    2)
        DEPLOY_MODE="fresh"
        echo ""
        echo "WARNING: This will DESTROY all data on the remote host!"
        echo "         - PostgreSQL database (all scan results, users, tenants)"
        echo "         - Redis data"
        echo "         - Application logs and config"
        echo "         - Nuclei templates cache"
        echo ""
        read -p "Type 'WIPE PRODUCTION' to confirm: " CONFIRM
        if [[ "$CONFIRM" != "WIPE PRODUCTION" ]]; then
            echo "Deployment aborted."
            exit 1
        fi
        ;;
    1)
        DEPLOY_MODE="update"
        read -p "Proceed with update deployment? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Deployment aborted."
            exit 1
        fi
        ;;
    *)
        echo "Invalid choice. Deployment aborted."
        exit 1
        ;;
esac

# ==============================================================================
# 1. Generate Setup Token (fresh install only)
# ==============================================================================
if [[ "$DEPLOY_MODE" == "fresh" ]]; then
    SETUP_TOKEN=$(openssl rand -hex 16)
    echo ""
    echo "=============================================================================="
    echo "SETUP TOKEN (save this — you will need it to access the setup wizard):"
    echo ""
    echo "    $SETUP_TOKEN"
    echo ""
    echo "=============================================================================="
    echo ""
    read -p "Press Enter once you have copied the token to continue..."
    echo ""
fi

# ==============================================================================
# 1.5 Wipe (fresh install only — runs BEFORE build/transfer)
# ==============================================================================
if [[ "$DEPLOY_MODE" == "fresh" ]]; then
    echo ">> Removing existing stack..."
    ssh "$REMOTE_HOST" "docker stack rm $STACK_NAME" || true

    echo ">> Waiting for services and containers to stop..."
    # Poll until all stack containers are gone (max 60s)
    for i in $(seq 1 30); do
        REMAINING=$(ssh "$REMOTE_HOST" "docker ps -q --filter label=com.docker.stack.namespace=$STACK_NAME 2>/dev/null | wc -l")
        if [[ "$REMAINING" -eq 0 ]]; then
            echo "   All containers stopped."
            break
        fi
        echo "   $REMAINING container(s) still running, waiting... ($i/30)"
        sleep 2
    done

    echo ">> Pruning stopped containers..."
    ssh "$REMOTE_HOST" "docker container prune -f --filter label=com.docker.stack.namespace=$STACK_NAME" || true

    echo ">> Removing data volumes..."
    for vol in $DATA_VOLUMES; do
        echo "   Removing volume $vol..."
        ssh "$REMOTE_HOST" "docker volume rm $vol 2>/dev/null" || echo "   (volume $vol not found, skipping)"
    done

    echo ">> Removing stack networks..."
    ssh "$REMOTE_HOST" "docker network rm ${STACK_NAME}_yads-internal ${STACK_NAME}_yads-frontend 2>/dev/null" || true

    echo ">> Removing old images..."
    ssh "$REMOTE_HOST" "docker rmi $REGISTRY_IMAGE $BACKUP_REGISTRY_IMAGE 2>/dev/null" || true

    echo ">> Wipe complete."
    echo ""
fi

# ==============================================================================
# 2. Local Build
# ==============================================================================
echo ">> Cleaning up old local images before build..."
docker rmi "$IMAGE_NAME" "$REGISTRY_IMAGE" "$BACKUP_IMAGE_NAME" "$BACKUP_REGISTRY_IMAGE" 2>/dev/null || true
docker image prune -f

echo ">> Building Docker image locally..."
# Build the 'prod' or 'release' target if applicable, or just default.
# The Dockerfile has a 'prod' stage.
docker build --target prod -t "$IMAGE_NAME" .
# Tag the image with the registry URL expected by the Swarm stack
docker tag "$IMAGE_NAME" "$REGISTRY_IMAGE"

echo ">> Building backup container image..."
docker build -t "$BACKUP_IMAGE_NAME" backup/
docker tag "$BACKUP_IMAGE_NAME" "$BACKUP_REGISTRY_IMAGE"

# ==============================================================================
# 3. Image Transfer
# ==============================================================================
echo ">> Compressing Docker image to $IMAGE_ARCHIVE..."
# Save the REGISTRY_IMAGE (not just local tag) so it loads with the correct name on remote
docker save "$REGISTRY_IMAGE" | gzip > "$IMAGE_ARCHIVE"

echo ">> Compressing backup image to $BACKUP_IMAGE_ARCHIVE..."
docker save "$BACKUP_REGISTRY_IMAGE" | gzip > "$BACKUP_IMAGE_ARCHIVE"

echo ">> Ensuring remote directory exists..."
ssh "$REMOTE_HOST" "mkdir -p $REMOTE_DEPLOY_DIR"

echo ">> Transferring compressed images to remote host..."
scp "$IMAGE_ARCHIVE" "$REMOTE_HOST:$REMOTE_DEPLOY_DIR/"
scp "$BACKUP_IMAGE_ARCHIVE" "$REMOTE_HOST:$REMOTE_DEPLOY_DIR/"

echo ">> Loading images on remote host..."
ssh "$REMOTE_HOST" "gunzip -c $REMOTE_DEPLOY_DIR/$IMAGE_ARCHIVE | docker load"
ssh "$REMOTE_HOST" "gunzip -c $REMOTE_DEPLOY_DIR/$BACKUP_IMAGE_ARCHIVE | docker load"

echo ">> Cleaning up local archives..."
rm -f "$IMAGE_ARCHIVE" "$BACKUP_IMAGE_ARCHIVE"

# ==============================================================================
# 4. Config Transfer
# ==============================================================================
echo ">> Transferring configuration files..."
ssh "$REMOTE_HOST" "mkdir -p $REMOTE_DEPLOY_DIR"
scp "$DOCKER_COMPOSE_FILE" "$REMOTE_HOST:$REMOTE_DEPLOY_DIR/"

# If .env exists, transfer it too
if [ -f .env ]; then
    echo ">> Found .env, transferring..."
    scp .env "$REMOTE_HOST:$REMOTE_DEPLOY_DIR/"
fi

# Inject setup token into remote .env for fresh installs
if [[ "$DEPLOY_MODE" == "fresh" && -n "$SETUP_TOKEN" ]]; then
    echo ">> Writing SETUP_TOKEN to remote .env..."
    ssh "$REMOTE_HOST" "cd $REMOTE_DEPLOY_DIR && (grep -q '^SETUP_TOKEN=' .env 2>/dev/null && sed -i 's/^SETUP_TOKEN=.*/SETUP_TOKEN=$SETUP_TOKEN/' .env || echo 'SETUP_TOKEN=$SETUP_TOKEN' >> .env)"
fi

# ==============================================================================
# 4.5 Ensure Backup Directories Exist on Remote
# ==============================================================================
echo ">> Creating backup directories on remote host..."
ssh "$REMOTE_HOST" 'mkdir -p "/mnt/backups/yads/daily" "/mnt/backups/yads/monthly"'

# ==============================================================================
# 5. Deployment
# ==============================================================================
echo ">> Deploying stack on remote host..."
# We need to tell docker stack deploy where the files are.
# Note: Variables in .env are automatically picked up if in the same dir.
ssh "$REMOTE_HOST" "cd $REMOTE_DEPLOY_DIR && set -a && [ -f .env ] && source .env; set +a && docker stack deploy -c $DOCKER_COMPOSE_FILE $STACK_NAME"

# ==============================================================================
# 6. Force Update (skip on fresh install — services are already new)
# ==============================================================================
if [[ "$DEPLOY_MODE" != "fresh" ]]; then
    echo ">> Forcing service updates to pick up new image..."
    for service in $SERVICES_TO_UPDATE; do
        echo "   Updating $service..."
        # Use the correct image for each service
        if [[ "$service" == *"backup"* ]]; then
            UPDATE_IMAGE="$BACKUP_REGISTRY_IMAGE"
        else
            UPDATE_IMAGE="$REGISTRY_IMAGE"
        fi
        ssh "$REMOTE_HOST" "docker service update --force --image $UPDATE_IMAGE $service" || echo "Warning: Failed to update $service (it might not be running yet)"
    done
fi

echo "=============================================================================="
if [[ "$DEPLOY_MODE" == "fresh" ]]; then
    echo "Fresh Install Complete!"
    echo "The setup wizard will be available at the application URL."
else
    echo "Deployment Complete!"
fi
echo "=============================================================================="
