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

# ==============================================================================
# Safety Check
# ==============================================================================
echo "=============================================================================="
echo "MANUAL DEPLOYMENT TO PRODUCTION"
echo "=============================================================================="
echo "Remote Host:    $REMOTE_HOST"
echo "Stack Name:     $STACK_NAME"
echo "Image Name:     $IMAGE_NAME"
echo "Compose File:   $DOCKER_COMPOSE_FILE"
echo "=============================================================================="
read -p "Are you sure you want to proceed with deployment? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment aborted."
    exit 1
fi

# ==============================================================================
# 1. Local Build
# ==============================================================================
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
# 2. Image Transfer
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
# 3. Config Transfer
# ==============================================================================
echo ">> Transferring configuration files..."
ssh "$REMOTE_HOST" "mkdir -p $REMOTE_DEPLOY_DIR"
scp "$DOCKER_COMPOSE_FILE" "$REMOTE_HOST:$REMOTE_DEPLOY_DIR/"

# If .env exists, transfer it too
if [ -f .env ]; then
    echo ">> Found .env, transferring..."
    scp .env "$REMOTE_HOST:$REMOTE_DEPLOY_DIR/"
fi

# ==============================================================================
# 3.5 Ensure Backup Directories Exist on Remote
# ==============================================================================
echo ">> Creating backup directories on remote host..."
ssh "$REMOTE_HOST" 'mkdir -p "/mnt/backups/yads/daily" "/mnt/backups/yads/monthly"'

# ==============================================================================
# 4. Deployment
# ==============================================================================
echo ">> Deploying stack on remote host..."
# We need to tell docker stack deploy where the files are.
# Note: Variables in .env are automatically picked up if in the same dir.
ssh "$REMOTE_HOST" "cd $REMOTE_DEPLOY_DIR && set -a && [ -f .env ] && source .env; set +a && docker stack deploy -c $DOCKER_COMPOSE_FILE $STACK_NAME"

# ==============================================================================
# 5. Force Update
# ==============================================================================
echo ">> Forcing service updates to pick up new image..."
for service in $SERVICES_TO_UPDATE; do
    echo "   Updating $service..."
    # We use --force to make sure it pulls/uses the image we just loaded, even if the tag didn't change (latest)
    # Actually, with 'docker load', the image ID updates for the tag.
    # 'docker service update --force' ensures tasks are re-scheduled.
    ssh "$REMOTE_HOST" "docker service update --force $service" || echo "Warning: Failed to update $service (it might not be running yet)"
done

echo "=============================================================================="
echo "Deployment Complete!"
echo "=============================================================================="
