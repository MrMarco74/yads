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
if git grep -E '(AIza[0-9A-Za-z\\-_]{35}|AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36})' -- '*.py' '*.js' '*.yml' '*.yaml' ':!venv/*' ':!.venv/*' &>/dev/null; then
    echo -e "${RED}FAIL${NC}"
    echo -e "${RED}ERROR: Potential hardcoded API keys found in tracked files!${NC}"
    git grep -n -E '(AIza[0-9A-Za-z\\-_]{35}|AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36})' -- '*.py' '*.js' '*.yml' '*.yaml' ':!venv/*' ':!.venv/*' || true
    SECURITY_ERRORS=$((SECURITY_ERRORS + 1))
else
    echo -e "${GREEN}PASS${NC}"
fi

# Check 3: Verify no database backups in repository
echo -n "  [CHECK] No database backups in repository... "
if git ls-files | grep -E '\.(sql|sql\.gz|db|backup|bak)$' &>/dev/null; then
    echo -e "${RED}FAIL${NC}"
    echo -e "${RED}ERROR: Database backup files found in repository!${NC}"
    git ls-files | grep -E '\.(sql|sql\.gz|db|backup|bak)$'
    SECURITY_ERRORS=$((SECURITY_ERRORS + 1))
else
    echo -e "${GREEN}PASS${NC}"
fi

# Check 4: Verify no .env files are tracked
echo -n "  [CHECK] No .env files tracked in Git... "
if git ls-files | grep -E '\.env(\.|$)' &>/dev/null; then
    echo -e "${RED}FAIL${NC}"
    echo -e "${RED}ERROR: .env files found in repository!${NC}"
    git ls-files | grep -E '\.env(\.|$)'
    SECURITY_ERRORS=$((SECURITY_ERRORS + 1))
else
    echo -e "${GREEN}PASS${NC}"
fi

# Check 5: Scan for common password patterns in tracked files
echo -n "  [CHECK] No hardcoded passwords in code... "
if git grep -i -E '(password|passwd|pwd)\s*=\s*["\x27][^"\x27]{8,}["\x27]' -- '*.py' '*.js' '*.yml' '*.yaml' ':!venv/*' ':!.venv/*' | grep -v -E '(example|template|test|mock|placeholder|CHANGE_THIS)' &>/dev/null; then
    echo -e "${RED}WARNING${NC}"
    echo -e "${RED}WARNING: Potential hardcoded passwords found. Please review:${NC}"
    git grep -n -i -E '(password|passwd|pwd)\s*=\s*["\x27][^"\x27]{8,}["\x27]' -- '*.py' '*.js' '*.yml' '*.yaml' ':!venv/*' ':!.venv/*' | grep -v -E '(example|template|test|mock|placeholder|CHANGE_THIS)' || true
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

# 3. Build Docker Images
echo -e "${BLUE}>> Building Docker Images (Nuitka Compiled)...${NC}"
# We build both services tagged as latest. We use the 'release' stage for compiled code.
docker build -t ${API_IMAGE_NAME}:latest --target release .
docker build -t ${WORKER_IMAGE_NAME}:latest --target release .

# 4. Save Images to Tarball
echo -e "${BLUE}>> Exporting Images to tar.gz (this may take a while)...${NC}"
docker save ${API_IMAGE_NAME}:latest ${WORKER_IMAGE_NAME}:latest | gzip > "$OUTPUT_DIR/$RELEASE_NAME/yads-images.tar.gz"

# 5. Copy Artifacts
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



# Docker Compose (Customer Version)
if [ -f "release_assets/docker-compose.customer.yml" ]; then
    cp release_assets/docker-compose.customer.yml "$OUTPUT_DIR/$RELEASE_NAME/docker-compose.yml"
else
    echo -e "${RED}Error: release_assets/docker-compose.customer.yml not found!${NC}"
    exit 1
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

# 8. Update Homepage
echo -e "${BLUE}>> Updating Homepage (DE & EN)...${NC}"

# Update DE
sed -i "s/yads_v[0-9.]*_customer_pkg.zip/${RELEASE_NAME}.zip/g" yads-homepage/de/support.html
sed -i "s/Download v[0-9.]* (.zip)/Download v${VERSION} (.zip)/g" yads-homepage/de/support.html
sed -i "s/SHA256:<\/strong> [a-f0-9]*/SHA256:<\/strong> ${SHA256}/g" yads-homepage/de/support.html

# Update EN
sed -i "s/yads_v[0-9.]*_customer_pkg.zip/${RELEASE_NAME}.zip/g" yads-homepage/en/support.html
sed -i "s/Download v[0-9.]* (.zip)/Download v${VERSION} (.zip)/g" yads-homepage/en/support.html
sed -i "s/SHA256:<\/strong> [a-f0-9]*/SHA256:<\/strong> ${SHA256}/g" yads-homepage/en/support.html

echo -e "Homepage updated with version ${VERSION} and new hash."

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

cat <<EOF > "$OUTPUT_DIR/version.json"
{
  "version": "$VERSION",
  "text": "$CHANGELOG_TEXT",
  "url": "https://yads-security.com/releases/${RELEASE_NAME}.zip"
}
EOF

echo -e "Generated ${BLUE}${OUTPUT_DIR}/version.json${NC}"

echo -e "${GREEN}=== Success! ===${NC}"
echo -e "Release Package: ${BLUE}${OUTPUT_DIR}/${RELEASE_NAME}.zip${NC}"
echo -e "SHA256: ${GREEN}${SHA256}${NC}"
echo -e "You can now send this zip file to the customer."
