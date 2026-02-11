#!/bin/sh
set -e

# Load password from shared config file (written by YADS setup wizard)
CONFIG_FILE="${CONFIG_PATH:-/app/data/config.env}"
if [ -z "$PGPASSWORD" ] || [ "$PGPASSWORD" = "changeme" ]; then
    if [ -f "$CONFIG_FILE" ]; then
        FILE_PW=$(grep -m1 '^POSTGRES_PASSWORD=' "$CONFIG_FILE" | cut -d'=' -f2-)
        if [ -n "$FILE_PW" ]; then
            export PGPASSWORD="$FILE_PW"
            echo "[INFO] Loaded PGPASSWORD from ${CONFIG_FILE}"
        fi
    fi
fi

# Configuration
DB_HOST="${DB_HOST:-db}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-yads}"
DB_USER="${DB_USER:-yads}"
BACKUP_BASE="${BACKUP_BASE:-/backups}"
APP_NAME="${APP_NAME:-yads}"
DAILY_RETENTION_DAYS="${DAILY_RETENTION_DAYS:-14}"
MIN_BACKUP_SIZE="${MIN_BACKUP_SIZE:-1024}"

TIMESTAMP=$(date +%Y-%m-%d_%H%M%S)
DAY_OF_MONTH=$(date +%d)
FILENAME="${APP_NAME}_${DB_NAME}_${TIMESTAMP}.sql.gz"

DAILY_DIR="${BACKUP_BASE}/daily"
MONTHLY_DIR="${BACKUP_BASE}/monthly"
SQL_TMPFILE=$(mktemp)

mkdir -p "$DAILY_DIR" "$MONTHLY_DIR"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting database backup..."
echo "[INFO] Host: ${DB_HOST}:${DB_PORT}, Database: ${DB_NAME}, User: ${DB_USER}"
echo "[INFO] Target: ${DAILY_DIR}/${FILENAME}"

# Perform backup — dump to temp file first so we catch pg_dump failures
if ! pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c --if-exists > "$SQL_TMPFILE"; then
    echo "[ERROR] pg_dump failed!"
    rm -f "$SQL_TMPFILE"
    exit 1
fi

gzip -c "$SQL_TMPFILE" > "${DAILY_DIR}/${FILENAME}"
rm -f "$SQL_TMPFILE"

# Validate backup is not empty
SIZE_BYTES=$(wc -c < "${DAILY_DIR}/${FILENAME}")
if [ "$SIZE_BYTES" -lt "$MIN_BACKUP_SIZE" ]; then
    echo "[ERROR] Backup file too small (${SIZE_BYTES} bytes) — likely empty or corrupt. Removing."
    rm -f "${DAILY_DIR}/${FILENAME}"
    exit 1
fi

SIZE=$(du -h "${DAILY_DIR}/${FILENAME}" | cut -f1)
echo "[SUCCESS] Backup completed: ${FILENAME} (${SIZE})"

# Monthly copy on the 1st
if [ "$DAY_OF_MONTH" = "01" ]; then
    echo "[INFO] First of month — copying to monthly archive..."
    cp "${DAILY_DIR}/${FILENAME}" "${MONTHLY_DIR}/${FILENAME}"
    echo "[SUCCESS] Monthly backup saved: ${FILENAME}"
fi

# Retention: delete daily backups older than configured days
echo "[INFO] Cleaning daily backups older than ${DAILY_RETENTION_DAYS} days..."
DELETED=$(find "$DAILY_DIR" -name "*.sql.gz" -mtime +${DAILY_RETENTION_DAYS} -print -delete | wc -l)
echo "[INFO] Deleted ${DELETED} old daily backup(s)."

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Backup process finished."
