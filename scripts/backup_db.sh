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
# Dump to temp file first so pg_dump failures are caught properly
# (piping to gzip masks pg_dump exit code in sh)
SQL_TMPFILE=$(mktemp)

if ! pg_dump "$DATABASE_URL" -c --if-exists > "$SQL_TMPFILE"; then
    echo "[ERROR] pg_dump failed!"
    rm -f "$SQL_TMPFILE"
    exit 1
fi

gzip -c "$SQL_TMPFILE" > "$BACKUP_FILE"
rm -f "$SQL_TMPFILE"

# Validate backup is not empty
SIZE_BYTES=$(wc -c < "$BACKUP_FILE")
if [ "$SIZE_BYTES" -lt 1024 ]; then
    echo "[ERROR] Backup file too small (${SIZE_BYTES} bytes) — likely empty or corrupt."
    rm -f "$BACKUP_FILE"
    exit 1
fi

echo "[SUCCESS] Backup completed successfully."
echo "[INFO] Size: $(du -h "$BACKUP_FILE" | cut -f1)"

# Optional: Retention Policy (Keep last 10 backups)
echo "[INFO] Cleaning up old backups (Keeping last 10)..."
ls -tp "${BACKUP_DIR}/pre_deploy_"* | grep -v '/$' | tail -n +11 | xargs -I {} rm -- {} || true

exit 0
