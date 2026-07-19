#!/bin/bash
set -e

# ==============================================================================
# One-time setup for YADS automated database backups
# Run this on the production host before first deployment
#
# Usage: BACKUP_ROOT=/path/to/backups ./setup_backup.sh
# ==============================================================================

BACKUP_ROOT="${BACKUP_ROOT:-./backups}"

echo "============================================="
echo "YADS Backup Setup"
echo "============================================="
echo "Backup root: ${BACKUP_ROOT}"

# Create directories
echo "[INFO] Creating backup directories..."
mkdir -p "${BACKUP_ROOT}/daily"
mkdir -p "${BACKUP_ROOT}/monthly"

# Validate writable
TEST_FILE="${BACKUP_ROOT}/.write_test"
if touch "$TEST_FILE" 2>/dev/null; then
    rm -f "$TEST_FILE"
    echo "[SUCCESS] Backup directory is writable."
else
    echo "[ERROR] Cannot write to ${BACKUP_ROOT}"
    echo "        Check mount/directory permissions."
    exit 1
fi

echo "[SUCCESS] Backup directories created:"
echo "  Daily:   ${BACKUP_ROOT}/daily/"
echo "  Monthly: ${BACKUP_ROOT}/monthly/"
echo ""
echo "Bind-mount ${BACKUP_ROOT} to /backups in the yads-backup service, then deploy it."
