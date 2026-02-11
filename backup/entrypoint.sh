#!/bin/sh
set -e

CRON_SCHEDULE="${CRON_SCHEDULE:-0 3 * * *}"

echo "============================================="
echo "YADS Database Backup Container"
echo "============================================="
echo "Schedule:  ${CRON_SCHEDULE}"
echo "DB Host:   ${DB_HOST:-db}:${DB_PORT:-5432}"
echo "DB Name:   ${DB_NAME:-yads}"
echo "Backup Dir: ${BACKUP_BASE:-/backups}"
echo "Retention: ${DAILY_RETENTION_DAYS:-14} days (daily)"
echo "============================================="

# BusyBox crond does not inherit environment variables,
# so we write them inline into the crontab entry.
# PGPASSWORD is omitted here — backup.sh reads it from the shared config file.
cat > /var/spool/cron/crontabs/root <<EOF
${CRON_SCHEDULE} DB_HOST=${DB_HOST:-db} DB_PORT=${DB_PORT:-5432} DB_NAME=${DB_NAME:-yads} DB_USER=${DB_USER:-yads} BACKUP_BASE=${BACKUP_BASE:-/backups} APP_NAME=${APP_NAME:-yads} DAILY_RETENTION_DAYS=${DAILY_RETENTION_DAYS:-14} CONFIG_PATH=${CONFIG_PATH:-/app/data/config.env} /usr/local/bin/backup.sh >> /proc/1/fd/1 2>&1
EOF

chmod 0600 /var/spool/cron/crontabs/root

# Run initial backup on startup
echo "[INFO] Running initial backup on startup..."
/usr/local/bin/backup.sh || echo "[WARN] Initial backup failed — will retry on next schedule."

# Start crond in foreground
echo "[INFO] Starting crond with schedule: ${CRON_SCHEDULE}"
exec crond -f -l 2
