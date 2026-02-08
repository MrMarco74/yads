#!/bin/bash
set -e

# ==============================================================================
# One-time setup for YADS automated database backups
# Run this on the production host before first deployment
# ==============================================================================

BACKUP_ROOT="/mnt/backups/yads"

echo "============================================="
echo "YADS Backup Setup"
echo "============================================="

# Check mount exists
if [ ! -d "/mnt/backup-storage" ]; then
    echo "[ERROR] /mnt/backup-storage is not mounted."
    echo "        Please mount the Hetzner Storage Box first."
    exit 1
fi

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
    echo "        Check mount permissions."
    exit 1
fi

echo "[SUCCESS] Backup directories created:"
echo "  Daily:   ${BACKUP_ROOT}/daily/"
echo "  Monthly: ${BACKUP_ROOT}/monthly/"
echo ""
echo "You can now deploy the yads-backup service."
