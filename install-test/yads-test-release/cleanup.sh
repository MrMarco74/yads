#!/bin/bash
set -e

# YADS Cleanup & Reset Script
# Use this to completely wipe a YADS installation for testing.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}==============================================================================${NC}"
echo -e "${YELLOW}                   YADS Cleanup & Reset Script                               ${NC}"
echo -e "${YELLOW}==============================================================================${NC}"
echo ""

# 1. Stop Docker Containers and Remove Volumes/Networks
if [ -f docker-compose.yml ]; then
    echo -e "${YELLOW}[1/3] Stopping Docker resources...${NC}"
    if docker compose version &>/dev/null; then
        docker compose down -v --remove-orphans
    else
        docker-compose down -v --remove-orphans
    fi
    echo -e "${GREEN}✓ Docker resources cleaned up.${NC}"
else
    echo -e "${YELLOW}[1/3] No docker-compose.yml found, skipping Docker cleanup.${NC}"
fi

# 2. Remove configuration files
echo -e "${YELLOW}[2/3] Removing configuration files...${NC}"
FILES_TO_REMOVE=(".env" "nginx/" "certs/")

for item in "${FILES_TO_REMOVE[@]}"; do
    if [ -e "$item" ]; then
        rm -rf "$item"
        echo "  - Removed $item"
    fi
done
echo -e "${GREEN}✓ Configuration files removed.${NC}"

# 3. Docker logout (optional but clean)
echo -e "${YELLOW}[3/3] Registry Logout...${NC}"
docker logout registry.yads-security.com &>/dev/null || true
echo -e "${GREEN}✓ Registry session cleaned up.${NC}"

echo ""
echo -e "${GREEN}Cleanup complete. Your environment is now in a fresh state.${NC}"
echo -e "${YELLOW}==============================================================================${NC}"
