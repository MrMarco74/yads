#!/bin/bash
# =============================================================================
# YADS — Test Environment Full Reset
# Removes ALL local YADS artifacts so the setup tool can be tested from scratch.
#
# ABSOLUTE PATHS ONLY — never touches the project source directory.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_TEST_DIR="$(dirname "$SCRIPT_DIR")/install-test"
RELEASE_DIR="$INSTALL_TEST_DIR/yads-test-release"

# Installer-generated files — live inside the unpacked release dir
INSTALLER_FILES=(
    "$RELEASE_DIR/.env"
    "$RELEASE_DIR/nginx"
    "$RELEASE_DIR/certs"
    "$RELEASE_DIR/data"
)

# Release archives (only removed with --all)
RELEASE_ARCHIVES=(
    "$INSTALL_TEST_DIR/yads-test-release.zip"
    "$INSTALL_TEST_DIR/yads-test-release.7z"
)

# ---------------------------------------------------------------------------
echo -e "${YELLOW}=============================================================================${NC}"
echo -e "${YELLOW}              YADS — Test Environment Full Reset                            ${NC}"
echo -e "${YELLOW}=============================================================================${NC}"
echo ""
echo -e "  Ziel-Verzeichnis: ${CYAN}$INSTALL_TEST_DIR${NC}"
echo ""
echo -e "${RED}  Dies löscht ALLE lokalen YADS-Container, Volumes, Netzwerke und${NC}"
echo -e "${RED}  alle vom Installer erzeugten Dateien in obigem Verzeichnis.${NC}"
echo ""
read -r -p "  Fortfahren? [j/N] " CONFIRM
if [[ ! "$CONFIRM" =~ ^[jJyY]$ ]]; then
    echo "Abgebrochen."
    exit 0
fi
echo ""

# ---------------------------------------------------------------------------
# 1. Stop & remove containers (by name pattern)
# ---------------------------------------------------------------------------
echo -e "${CYAN}[1/6] Container stoppen und entfernen...${NC}"
CONTAINERS=$(docker ps -a --filter "name=yads" --format "{{.Names}}" 2>/dev/null || true)
if [ -n "$CONTAINERS" ]; then
    while IFS= read -r c; do
        docker rm -f "$c" &>/dev/null && echo "  - Entfernt: $c"
    done <<< "$CONTAINERS"
else
    echo "  (keine YADS-Container gefunden)"
fi
echo -e "${GREEN}  ✓ Container bereinigt${NC}"

# ---------------------------------------------------------------------------
# 2. Remove volumes
# ---------------------------------------------------------------------------
echo -e "${CYAN}[2/6] Volumes entfernen...${NC}"
VOLUMES=$(docker volume ls --filter "name=yads" --format "{{.Name}}" 2>/dev/null || true)
if [ -n "$VOLUMES" ]; then
    while IFS= read -r v; do
        docker volume rm -f "$v" &>/dev/null && echo "  - Entfernt: $v"
    done <<< "$VOLUMES"
else
    echo "  (keine YADS-Volumes gefunden)"
fi
echo -e "${GREEN}  ✓ Volumes bereinigt${NC}"

# ---------------------------------------------------------------------------
# 3. Remove networks
# ---------------------------------------------------------------------------
echo -e "${CYAN}[3/6] Netzwerke entfernen...${NC}"
NETWORKS=$(docker network ls --filter "name=yads" --format "{{.Name}}" 2>/dev/null || true)
if [ -n "$NETWORKS" ]; then
    while IFS= read -r n; do
        docker network rm "$n" &>/dev/null && echo "  - Entfernt: $n" || true
    done <<< "$NETWORKS"
else
    echo "  (keine YADS-Netzwerke gefunden)"
fi
echo -e "${GREEN}  ✓ Netzwerke bereinigt${NC}"

# ---------------------------------------------------------------------------
# 4. Remove unpacked release directory
# ---------------------------------------------------------------------------
echo -e "${CYAN}[4/6] Ausgepacktes Release-Verzeichnis entfernen...${NC}"
if [ -d "$RELEASE_DIR" ]; then
    sudo rm -rf "$RELEASE_DIR" && echo "  - Entfernt: $RELEASE_DIR" || \
        echo -e "  ${RED}⚠ Fehler — bitte manuell: sudo rm -rf $RELEASE_DIR${NC}"
else
    echo "  (nicht vorhanden: $RELEASE_DIR)"
fi
echo -e "${GREEN}  ✓ Release-Verzeichnis bereinigt${NC}"

# ---------------------------------------------------------------------------
# 5. Remove installer-generated config files
# ---------------------------------------------------------------------------
echo -e "${CYAN}[5/6] Installer-Dateien entfernen...${NC}"
for f in "${INSTALLER_FILES[@]}"; do
    if [ -e "$f" ]; then
        rm -rf "$f" && echo "  - Entfernt: $f"
    fi
done
echo -e "${GREEN}  ✓ Installer-Dateien bereinigt${NC}"

# ---------------------------------------------------------------------------
# 6. Optionally remove release archives + registry logout
# ---------------------------------------------------------------------------
echo -e "${CYAN}[6/6] Abschluss...${NC}"
if [[ "${1:-}" == "--all" ]]; then
    for a in "${RELEASE_ARCHIVES[@]}"; do
        if [ -f "$a" ]; then
            rm -f "$a" && echo "  - Entfernt: $a"
        fi
    done
    echo "  (Release-Archive gelöscht)"
else
    echo "  (Release-Archive behalten — nutze --all um sie auch zu löschen)"
fi
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}=============================================================================${NC}"
echo -e "${GREEN}  ✓ Fertig — Umgebung ist sauber. Setup-Tool kann neu gestartet werden.${NC}"
echo -e "${GREEN}=============================================================================${NC}"
echo ""
