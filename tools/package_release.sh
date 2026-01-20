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

# 1. Verify we are in root
if [ ! -f "Dockerfile" ]; then
    echo -e "${RED}Error: specific Dockerfile not found. Please run this script from the project root.${NC}"
    exit 1
fi

# 2. Get Version
VERSION=$(grep 'VERSION: str =' yads/config.py | cut -d '"' -f 2)
echo -e "Detected Version: ${GREEN}${VERSION}${NC}"

RELEASE_NAME="${PROJECT_NAME}_v${VERSION}_customer_pkg"
mkdir -p "$OUTPUT_DIR/$RELEASE_NAME"

# 3. Build Docker Images
echo -e "${BLUE}>> Building Docker Images...${NC}"
# We build both services tagged as latest for simplicity in the customer load
docker build -t ${API_IMAGE_NAME}:latest --target prod .
docker build -t ${WORKER_IMAGE_NAME}:latest --target prod .

# 4. Save Images to Tarball
echo -e "${BLUE}>> Exporting Images to tar.gz (this may take a while)...${NC}"
docker save ${API_IMAGE_NAME}:latest ${WORKER_IMAGE_NAME}:latest | gzip > "$OUTPUT_DIR/$RELEASE_NAME/yads-images.tar.gz"

# 5. Copy Artifacts
echo -e "${BLUE}>> Copying Documentation and Configs...${NC}"

# Setup Guide
if [ -f "SETUP_GUIDE.md" ]; then
    cp SETUP_GUIDE.md "$OUTPUT_DIR/$RELEASE_NAME/README_SETUP.md" # Rename to README for visibility
else
    echo -e "${RED}Warning: SETUP_GUIDE.md not found!${NC}"
fi

# Additional Documentation
echo -e "${BLUE}>> Copying Additional Documentation...${NC}"
mkdir -p "$OUTPUT_DIR/$RELEASE_NAME/docs"

if [ -f "USER_GUIDE.md" ]; then
    cp USER_GUIDE.md "$OUTPUT_DIR/$RELEASE_NAME/docs/USER_GUIDE.md"
fi

if [ -f "TECHNICAL_GUIDE.md" ]; then
    cp TECHNICAL_GUIDE.md "$OUTPUT_DIR/$RELEASE_NAME/docs/TECHNICAL_GUIDE.md"
fi



# Docker Compose (Customer Version)
if [ -f "docker-compose.customer.yml" ]; then
    cp docker-compose.customer.yml "$OUTPUT_DIR/$RELEASE_NAME/docker-compose.yml"
else
    echo -e "${RED}Error: docker-compose.customer.yml not found!${NC}"
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

echo -e "${GREEN}=== Success! ===${NC}"
echo -e "Release Package: ${BLUE}${OUTPUT_DIR}/${RELEASE_NAME}.zip${NC}"
echo -e "SHA256: ${GREEN}${SHA256}${NC}"
echo -e "You can now send this zip file to the customer."
