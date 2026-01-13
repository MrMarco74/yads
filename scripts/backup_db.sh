#!/bin/bash
set -e

# Configuration
BACKUP_DIR="${LOG_DIR:-/app/logs}/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/pre_deploy_${TIMESTAMP}.sql.gz"

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

echo "[INFO] Starting Pre-Deployment Database Backup..."
echo "[INFO] Target: $BACKUP_FILE"

# Check if DATABASE_URL is set
if [ -z "$DATABASE_URL" ]; then
    echo "[ERROR] DATABASE_URL is not set."
    exit 1
fi

# Perform Backup
# We use pg_dump with the connection string.
# -Z 5: Compression level 5
# -c: Clean (DROP commands) - ensures clean restore
# --if-exists: used with -c
if pg_dump "$DATABASE_URL" -c --if-exists | gzip > "$BACKUP_FILE"; then
    echo "[SUCCESS] Backup completed successfully."
    echo "[INFO] Size: $(du -h "$BACKUP_FILE" | cut -f1)"
    
    # Optional: Retention Policy (Keep last 10 backups)
    echo "[INFO] Cleaning up old backups (Keeping last 10)..."
    ls -tp "${BACKUP_DIR}/pre_deploy_"* | grep -v '/$' | tail -n +11 | xargs -I {} rm -- {} || true
    
    exit 0
else
    echo "[ERROR] Backup failed!"
    # Remove partial file
    rm -f "$BACKUP_FILE"
    exit 1
fi
