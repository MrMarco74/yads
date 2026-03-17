#!/bin/bash
set -e

# YADS Test Release Bundler
# This script packages the latest installer, cleanup tools, and config files.

ROOT_DIR="/home/mrmarco/Documents/gitlab/yads"
INSTALL_TEST_DIR="$ROOT_DIR/install-test"
ASSETS_DIR="$ROOT_DIR/release_assets"
BUILD_DIR="$ROOT_DIR/temp_release_build"
OUTPUT_FILE="$INSTALL_TEST_DIR/yads-test-release.zip"

echo "=============================================================================="
echo "                   YADS — Test Release Packager                             "
echo "=============================================================================="

# 1. Build the .pyz installer first
echo "[1/4] Building installer package..."
python3 "$ASSETS_DIR/yads_installer/build.py"

# 2. Create a clean staging directory inside a temp dir
echo "[2/4] Preparing staging area..."
mkdir -p "$INSTALL_TEST_DIR"
PKG_NAME=$(basename "$OUTPUT_FILE" .zip)
STAGING_DIR=$(mktemp -d)
trap "rm -rf '$STAGING_DIR'" EXIT
BUILD_DIR="$STAGING_DIR/$PKG_NAME"
mkdir -p "$BUILD_DIR/docs"

# 3. Copy essential files
echo "[3/4] Copying release files..."
cp "$ASSETS_DIR/yads-setup.pyz"          "$BUILD_DIR/"
cp "$ASSETS_DIR/cleanup.sh"              "$BUILD_DIR/"
cp "$ASSETS_DIR/docker-compose.prod.yml" "$BUILD_DIR/docker-compose.yml"
cp "$ASSETS_DIR/nginx.conf.template"     "$BUILD_DIR/"
cp -r "$ROOT_DIR/monitoring"             "$BUILD_DIR/"
cp -r "$ROOT_DIR/keycloak"               "$BUILD_DIR/"
cp "$ROOT_DIR/cbom.json"                 "$BUILD_DIR/"
cp "$ROOT_DIR/sbom.json"                 "$BUILD_DIR/"
cp "$ROOT_DIR/docs/TECHNICAL_GUIDE.md"  "$BUILD_DIR/docs/"
cp "$ROOT_DIR/docs/USER_GUIDE.md"       "$BUILD_DIR/docs/"

# Special check for README_SETUP
if [ -f "$ROOT_DIR/releases/yads_v1.51.5_customer_pkg/README_SETUP.md" ]; then
    cp "$ROOT_DIR/releases/yads_v1.51.5_customer_pkg/README_SETUP.md" "$BUILD_DIR/"
fi

# 4. Compress everything into .zip
echo "[4/4] Creating zip archive..."
rm -f "$OUTPUT_FILE"
# Remove any leftover extracted directory (may be root-owned from Docker)
if [ -d "$INSTALL_TEST_DIR/$PKG_NAME" ]; then
    sudo rm -rf "$INSTALL_TEST_DIR/$PKG_NAME" 2>/dev/null || \
        echo "  Warning: could not remove leftover $INSTALL_TEST_DIR/$PKG_NAME — run sudo rm -rf manually if unzip fails"
fi
cd "$STAGING_DIR"
zip -r "$OUTPUT_FILE" "$PKG_NAME" > /dev/null

echo ""
echo -e "\033[0;32m✓ Success: Test release created at $OUTPUT_FILE\033[0m"
echo "=============================================================================="
echo ""

# Optional: launch installer directly from the freshly built .pyz
if [[ "${1}" == "--run" || "${1}" == "-r" ]]; then
    echo -e "\033[0;36m▶ Starte Installer direkt aus der frisch gebauten .pyz …\033[0m"
    # Unpack into install-test/, then cd into the release subdirectory so that
    # docker-compose.yml, .env and all installer artifacts live in the same place.
    cd "$INSTALL_TEST_DIR"
    unzip -q -o "$(basename "$OUTPUT_FILE")" -d . 2>/dev/null || true
    cd "$INSTALL_TEST_DIR/yads-test-release"
    python3 "$ASSETS_DIR/yads-setup.pyz"
else
    echo -e "  Tipp: Mit \033[1m./build_test_release.sh --run\033[0m wird der Installer direkt gestartet."
fi
