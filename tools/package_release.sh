#!/bin/bash
set -e

# Configuration
PROJECT_NAME="yads"
API_IMAGE_NAME="yads-api"
WORKER_IMAGE_NAME="yads-worker"
OUTPUT_DIR="releases"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== YADS Release Packager ===${NC}"

# 1. Ensure we are in the project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

if [ ! -f "Dockerfile" ]; then
    echo -e "${RED}Error: Dockerfile not found. Could not determine project root.${NC}"
    exit 1
fi

# 2. Get Version
VERSION=$(grep 'VERSION: str =' yads/config.py | cut -d '"' -f 2)
echo -e "Detected Version: ${GREEN}${VERSION}${NC}"

# 2.1. Get Release Channel (from environment, default to 'stable')
RELEASE_CHANNEL="${RELEASE_CHANNEL:-stable}"
if [ "$RELEASE_CHANNEL" = "beta" ]; then
    echo -e "Release Channel: ${BLUE}🔷 BETA${NC}"
else
    echo -e "Release Channel: ${GREEN}🟢 STABLE${NC}"
fi

RELEASE_NAME="${PROJECT_NAME}_v${VERSION}_customer_pkg"
mkdir -p "$OUTPUT_DIR/$RELEASE_NAME"

# 2.5. PRE-FLIGHT SECURITY VALIDATION
echo -e "${BLUE}>> Running Pre-Flight Security Checks...${NC}"

SECURITY_ERRORS=0

# Check 1: Ensure data/config.env is NOT tracked in Git
echo -n "  [CHECK] data/config.env not in Git... "
if git ls-files --error-unmatch data/config.env &>/dev/null; then
    echo -e "${RED}FAIL${NC}"
    echo -e "${RED}ERROR: data/config.env is tracked in Git! Remove it with: git rm --cached data/config.env${NC}"
    SECURITY_ERRORS=$((SECURITY_ERRORS + 1))
else
    echo -e "${GREEN}PASS${NC}"
fi

# Check 2: Scan for hardcoded API keys in tracked files
echo -n "  [CHECK] No hardcoded API keys in code... "
# Common API key patterns (Google, AWS, GitHub, etc.)
# Exclude venv and .venv directories to avoid false positives from dependencies
if git grep -E '(AIza[0-9A-Za-z\\-_]{35}|AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36})' -- '*.py' '*.js' '*.yml' '*.yaml' ':!venv/*' ':!.venv/*' ':!testlab/*' &>/dev/null; then
    echo -e "${RED}FAIL${NC}"
    echo -e "${RED}ERROR: Potential hardcoded API keys found in tracked files!${NC}"
    git grep -n -E '(AIza[0-9A-Za-z\\-_]{35}|AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36})' -- '*.py' '*.js' '*.yml' '*.yaml' ':!venv/*' ':!.venv/*' ':!testlab/*' || true
    SECURITY_ERRORS=$((SECURITY_ERRORS + 1))
else
    echo -e "${GREEN}PASS${NC}"
fi

# Check 3: Verify no database backups in repository
echo -n "  [CHECK] No database backups in repository... "
if git ls-files | grep -E '\.(sql|sql\.gz|db|backup|bak)$' | grep -v '^testlab/' &>/dev/null; then
    echo -e "${RED}FAIL${NC}"
    echo -e "${RED}ERROR: Database backup files found in repository!${NC}"
    git ls-files | grep -E '\.(sql|sql\.gz|db|backup|bak)$' | grep -v '^testlab/'
    SECURITY_ERRORS=$((SECURITY_ERRORS + 1))
else
    echo -e "${GREEN}PASS${NC}"
fi

# Check 4: Verify no .env files are tracked (.env.example is allowed)
echo -n "  [CHECK] No .env files tracked in Git... "
if git ls-files | grep -E '(^|/)\.env$|(^|/)\.env\.(local|prod|production|staging|development)$' &>/dev/null; then
    echo -e "${RED}FAIL${NC}"
    echo -e "${RED}ERROR: .env files found in repository!${NC}"
    git ls-files | grep -E '(^|/)\.env$|(^|/)\.env\.(local|prod|production|staging|development)$'
    SECURITY_ERRORS=$((SECURITY_ERRORS + 1))
else
    echo -e "${GREEN}PASS${NC}"
fi

# Check 5: Scan for common password patterns in tracked files (excludes venv/site-packages)
echo -n "  [CHECK] No hardcoded passwords in code... "
_PW_EXCLUDE='(example|template|test|mock|placeholder|CHANGE_THIS|changeme|your-|_invalid_password|_wrong_password|_failure.*password|password.*failure|LOGIN_FAILURE)'
_PW_PATHS=('*.py' '*.js' '*.yml' '*.yaml'
           ':(exclude,glob)venv/**' ':(exclude,glob).venv/**' ':(exclude,glob).rel_venv/**'
           ':(exclude,glob)*/site-packages/**' ':(exclude)*.example')
if git grep -i -E '(password|passwd|pwd)\s*=\s*["\x27][^"\x27]{8,}["\x27]' -- "${_PW_PATHS[@]}" \
   | grep -v -E "$_PW_EXCLUDE" &>/dev/null; then
    echo -e "${RED}WARNING${NC}"
    echo -e "${RED}WARNING: Potential hardcoded passwords found. Please review:${NC}"
    git grep -n -i -E '(password|passwd|pwd)\s*=\s*["\x27][^"\x27]{8,}["\x27]' -- "${_PW_PATHS[@]}" \
      | grep -v -E "$_PW_EXCLUDE" || true
    # Don't fail build, just warn
else
    echo -e "${GREEN}PASS${NC}"
fi

# Exit if critical errors found
if [ $SECURITY_ERRORS -gt 0 ]; then
    echo -e "${RED}=== SECURITY VALIDATION FAILED ===${NC}"
    echo -e "${RED}Found $SECURITY_ERRORS critical security issue(s). Fix them before releasing.${NC}"
    exit 1
fi

echo -e "${GREEN}>> All Security Checks Passed!${NC}"

# 2.6. Generate Bill of Materials (SBOM & CBOM)
# IMPORTANT: This must happen BEFORE Docker build/compilation
# because after Nuitka compilation we lose the source code information
echo -e "${BLUE}>> Generating Bill of Materials (SBOM & CBOM)...${NC}"
python3 scripts/generate_bom.py --output-dir releases/ || {
    echo -e "${RED}Warning: BOM generation failed. Continuing without BOM files.${NC}"
}

# Copy BOM files to release directory and uploads
if [ -f "releases/sbom.json" ]; then
    echo -e "  ${GREEN}✓${NC} SBOM generated successfully"
    mkdir -p "$OUTPUT_DIR/$RELEASE_NAME"
    cp releases/sbom.json releases/sbom.xml "$OUTPUT_DIR/$RELEASE_NAME/" 2>/dev/null || true
fi
if [ -f "releases/cbom.json" ]; then
    echo -e "  ${GREEN}✓${NC} CBOM generated successfully"
    mkdir -p "$OUTPUT_DIR/$RELEASE_NAME"
    cp releases/cbom.json releases/cbom.xml "$OUTPUT_DIR/$RELEASE_NAME/" 2>/dev/null || true
fi

# 3. Build Docker Images
REGISTRY="registry.yads-security.com/yads"

echo -e "${BLUE}>> Cleaning up old images before build...${NC}"
docker rmi ${API_IMAGE_NAME}:latest ${WORKER_IMAGE_NAME}:latest 2>/dev/null || true
docker image prune -f

echo -e "${BLUE}>> Building API image (--target api, no scanner tools)...${NC}"
docker build \
  --target api \
  --build-arg YADS_GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)" \
  -t ${API_IMAGE_NAME}:latest \
  -t ${API_IMAGE_NAME}:${VERSION} \
  -t ${REGISTRY}/yads-api:latest \
  -t ${REGISTRY}/yads-api:${VERSION} \
  .

echo -e "${BLUE}>> Building Worker image (Dockerfile.worker, pre-baked tools base)...${NC}"
TOOLS_VERSION=$(cat "${PROJECT_ROOT}/tools/TOOLS_VERSION")
TOOLS_IMAGE="${REGISTRY}/yads-tools:${TOOLS_VERSION}"
if [ -f "Dockerfile.worker" ]; then
  docker build \
    -f Dockerfile.worker \
    --build-arg TOOLS_IMAGE="${TOOLS_IMAGE}" \
    --build-arg YADS_GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)" \
    -t ${WORKER_IMAGE_NAME}:latest \
    -t ${WORKER_IMAGE_NAME}:${VERSION} \
    -t ${REGISTRY}/yads-worker:latest \
    -t ${REGISTRY}/yads-worker:${VERSION} \
    .
else
  echo -e "${YELLOW}Dockerfile.worker not found — falling back to --target worker (slow).${NC}"
  docker build \
    --target worker \
    -t ${WORKER_IMAGE_NAME}:latest \
    -t ${WORKER_IMAGE_NAME}:${VERSION} \
    -t ${REGISTRY}/yads-worker:latest \
    -t ${REGISTRY}/yads-worker:${VERSION} \
    .
fi

# 4. Push Images to Customer Registry
echo -e "${BLUE}>> Pushing images to registry.yads-security.com...${NC}"
echo "  Make sure you are logged in: docker login registry.yads-security.com"
docker push ${REGISTRY}/yads-api:${VERSION}
docker push ${REGISTRY}/yads-api:latest
docker push ${REGISTRY}/yads-worker:${VERSION}
docker push ${REGISTRY}/yads-worker:latest
echo -e "${GREEN}>> Images pushed successfully.${NC}"

# 4. Copy Artifacts
echo -e "${BLUE}>> Copying Documentation and Configs...${NC}"

# Setup Guide
if [ -f "release_assets/SETUP_GUIDE.md" ]; then
    cp release_assets/SETUP_GUIDE.md "$OUTPUT_DIR/$RELEASE_NAME/README_SETUP.md" # Rename to README for visibility
else
    echo -e "${RED}Warning: release_assets/SETUP_GUIDE.md not found!${NC}"
fi

# Additional Documentation
echo -e "${BLUE}>> Copying Additional Documentation...${NC}"
mkdir -p "$OUTPUT_DIR/$RELEASE_NAME/docs"

if [ -f "docs/USER_GUIDE.md" ]; then
    cp docs/USER_GUIDE.md "$OUTPUT_DIR/$RELEASE_NAME/docs/USER_GUIDE.md"
fi

if [ -f "docs/TECHNICAL_GUIDE.md" ]; then
    cp docs/TECHNICAL_GUIDE.md "$OUTPUT_DIR/$RELEASE_NAME/docs/TECHNICAL_GUIDE.md"
fi



# Docker Compose and Setup Scripts (Customer Version)
if [ -f "release_assets/docker-compose.customer.yml" ]; then
    cp release_assets/docker-compose.customer.yml "$OUTPUT_DIR/$RELEASE_NAME/docker-compose.yml"
else
    echo -e "${RED}Error: release_assets/docker-compose.customer.yml not found!${NC}"
    exit 1
fi

# Build and include the GUI installer
echo -e "${BLUE}>> Building GUI installer (yads-setup.pyz)...${NC}"
python3 release_assets/yads_installer/build.py
cp release_assets/yads-setup.pyz "$OUTPUT_DIR/$RELEASE_NAME/"
chmod +x "$OUTPUT_DIR/$RELEASE_NAME/yads-setup.pyz"

# Also copy monitoring and keycloak configs
if [ -d "monitoring" ]; then
    cp -r monitoring "$OUTPUT_DIR/$RELEASE_NAME/"
fi
if [ -d "keycloak" ]; then
    cp -r keycloak "$OUTPUT_DIR/$RELEASE_NAME/"
fi

if [ -f "release_assets/nginx.conf.template" ]; then
    cp release_assets/nginx.conf.template "$OUTPUT_DIR/$RELEASE_NAME/"
fi

# 6. Create Archive
echo -e "${BLUE}>> Zipping Release Bundle...${NC}"
cd "$OUTPUT_DIR"
rm -f "${RELEASE_NAME}.zip"
zip -r "${RELEASE_NAME}.zip" "$RELEASE_NAME"
cd ..

# 7. Generate Hash
echo -e "${BLUE}>> Generating SHA256 Hash...${NC}"
ZIP_FILE="$OUTPUT_DIR/${RELEASE_NAME}.zip"
SHA256=$(sha256sum "$ZIP_FILE" | awk '{print $1}')
echo -e "Hash: ${GREEN}${SHA256}${NC}"

# 8. Update Changelog placeholders (download buttons populated dynamically via version.json)
echo -e "${BLUE}>> Updating Changelog SHA256 placeholders...${NC}"
sed -i "s/\[SHA256_HASH_TBD\]/${SHA256}/g" yads/core/seeding.py
sed -i "s/\[SHA256_HASH_TBD\]/${SHA256}/g" yads-homepage/de/changes.html
sed -i "s/\[SHA256_HASH_TBD\]/${SHA256}/g" yads-homepage/en/changes.html
echo -e "  Changelog SHA256 updated. Download buttons are populated dynamically via version.json."

# 9. Generate version.json for Update Checker
echo -e "${BLUE}>> Generating version.json for Update Checker...${NC}"
# Extract latest changes from seeding.py (simplistic approach: get second match for 'content="""' as first is likely seed_changelog)
# Actually, better: use a small python snippet to extract precisely what we want if seeding.py is predictable.
# For now, we'll use a safer approach: extract the text of the LATEST version which we know is $VERSION.

CHANGELOG_TEXT=$(python3 -c "
import sys
content = open('yads/core/seeding.py').read()
version = '$VERSION'
try:
    start_marker = f'ChangelogEntry(\n                title=\"'
    # This is a bit brittle, let's try finding by version
    v_marker = f'version=\"{version}\"'
    v_pos = content.find(v_marker)
    if v_pos != -1:
        # Look backwards for content=\"\"\"
        c_start = content.rfind('content=\"\"\"', 0, v_pos)
        if c_start != -1:
            c_end = content.find('\"\"\"', c_start + 11)
            raw_text = content[c_start+11:c_end].strip()
            # Clean HTML tags for notification text (roughly)
            import re
            clean = re.sub('<[^<]+?>', '', raw_text)
            print(clean.replace('\n', ' ').strip()[:200] + '...')
        else:
            print(f'New features in v{version}!')
    else:
        print(f'New features in v{version}!')
except Exception as e:
    print(f'New features in v{version}!')
")

# Generate channel-specific version file
# stable -> version.json (backwards compatible with existing update checker)
# beta -> version-beta.json
if [ "$RELEASE_CHANNEL" = "beta" ]; then
    VERSION_FILE="version-beta.json"
else
    VERSION_FILE="version.json"
fi

cat <<EOF > "$OUTPUT_DIR/$VERSION_FILE"
{
  "version": "$VERSION",
  "channel": "$RELEASE_CHANNEL",
  "text": "$CHANGELOG_TEXT",
  "url": "https://yads-security.com/releases/${RELEASE_NAME}.zip",
  "sha256": "$SHA256"
}
EOF

echo -e "Generated ${BLUE}${OUTPUT_DIR}/${VERSION_FILE}${NC} (channel: ${RELEASE_CHANNEL})"

echo -e "${GREEN}=== Success! ===${NC}"
echo -e "Release Package: ${BLUE}${OUTPUT_DIR}/${RELEASE_NAME}.zip${NC}"
echo -e "SHA256: ${GREEN}${SHA256}${NC}"
echo -e "You can now send this zip file to the customer."
