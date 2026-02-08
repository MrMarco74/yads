#!/bin/sh
set -e

# Configuration
DB_HOST="${DB_HOST:-db}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-yads}"
DB_USER="${DB_USER:-yads}"
BACKUP_BASE="${BACKUP_BASE:-/backups}"
APP_NAME="${APP_NAME:-yads}"
DAILY_RETENTION_DAYS="${DAILY_RETENTION_DAYS:-14}"

TIMESTAMP=$(date +%Y-%m-%d_%H%M%S)
DAY_OF_MONTH=$(date +%d)
FILENAME="${APP_NAME}_${DB_NAME}_${TIMESTAMP}.sql.gz"

DAILY_DIR="${BACKUP_BASE}/daily"
MONTHLY_DIR="${BACKUP_BASE}/monthly"

mkdir -p "$DAILY_DIR" "$MONTHLY_DIR"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting database backup..."
echo "[INFO] Host: ${DB_HOST}:${DB_PORT}, Database: ${DB_NAME}, User: ${DB_USER}"
echo "[INFO] Target: ${DAILY_DIR}/${FILENAME}"

# Perform backup
if pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c --if-exists | gzip > "${DAILY_DIR}/${FILENAME}"; then
    SIZE=$(du -h "${DAILY_DIR}/${FILENAME}" | cut -f1)
    echo "[SUCCESS] Backup completed: ${FILENAME} (${SIZE})"
else
    echo "[ERROR] Backup failed!"
    rm -f "${DAILY_DIR}/${FILENAME}"
    exit 1
fi

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
