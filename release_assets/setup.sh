#!/bin/bash
set -e

# YADS Customer Setup Script
# This script helps you configure YADS for your environment.

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}==============================================================================${NC}"
echo -e "${BLUE}                   YADS - Yet Another Deployment System                       ${NC}"
echo -e "${BLUE}                          Customer Setup Wizard                               ${NC}"
echo -e "${BLUE}==============================================================================${NC}"
echo ""

# 1. Dependency Checks
echo -e "${YELLOW}>> Checking Dependencies...${NC}"
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: docker is not installed.${NC}"
    exit 1
fi
if ! docker compose version &> /dev/null; then
    echo -e "${RED}Error: docker compose is not installed or too old.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Dependencies OK${NC}"
echo ""

# 2. Docker Host Configuration
echo -e "${YELLOW}>> Docker Host Configuration${NC}"
echo "Where will YADS be deployed?"
echo "  1) Local Machine (localhost)"
echo "  2) Remote Docker Host (via DOCKER_HOST env var)"
read -p "Choose [1/2, default 1]: " HOST_CHOICE
HOST_CHOICE=${HOST_CHOICE:-1}

if [ "$HOST_CHOICE" == "2" ]; then
    read -p "Enter DOCKER_HOST (e.g. ssh://user@host): " D_HOST
    export DOCKER_HOST="$D_HOST"
    echo -e "DOCKER_HOST set to: ${BLUE}$DOCKER_HOST${NC}"
fi
echo ""

# 3. Port and SSL Configuration
echo -e "${YELLOW}>> Network & SSL Configuration${NC}"
read -p "On which port should the API be accessible? [default 80]: " API_PORT
API_PORT=${API_PORT:-80}

USE_SSL="n"
if [ "$API_PORT" == "443" ] || [ "$API_PORT" == "8443" ]; then
    echo "Common SSL port detected."
    USE_SSL="y"
else
    read -p "Do you want to use SSL (https)? (y/N): " USE_SSL
fi

if [[ "$USE_SSL" =~ ^[Yy]$ ]]; then
    echo "SSL Configuration:"
    echo "  1) Self-signed certificate (generated now)"
    echo "  2) Custom certificates (you provide the paths)"
    read -p "Choose [1/2, default 1]: " SSL_CHOICE
    SSL_CHOICE=${SSL_CHOICE:-1}
    
    if [ "$SSL_CHOICE" == "1" ]; then
        echo "Generating self-signed certificate..."
        mkdir -p certs
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout certs/yads.key -out certs/yads.crt \
            -subj "/C=DE/ST=State/L=City/O=YADS/OU=IT/CN=localhost"
        SSL_CERT_PATH="./certs/yads.crt"
        SSL_KEY_PATH="./certs/yads.key"
    else
        read -p "Path to SSL Certificate (.crt): " SSL_CERT_PATH
        read -p "Path to SSL Key (.key): " SSL_KEY_PATH
    fi
fi
echo ""

# 4. Credentials
echo -e "${YELLOW}>> Secret Configuration${NC}"
if [ -f .env ]; then
    read -p ".env file already exists. Overwrite with new secrets? (y/N): " OVERWRITE_ENV
else
    OVERWRITE_ENV="y"
fi

if [[ "$OVERWRITE_ENV" =~ ^[Yy]$ ]]; then
    POSTGRES_PASSWORD=$(openssl rand -base64 24)
    SECRET_KEY=$(openssl rand -hex 32)
    
    cat <<EOF > .env
# --- Database ---
POSTGRES_PASSWORD=$POSTGRES_PASSWORD

# --- Security ---
SECRET_KEY=$SECRET_KEY

# --- Network ---
API_PORT=$API_PORT
EOF
    echo -e "${GREEN}✓ Generated secure passwords in .env${NC}"
fi
echo ""

# 5. Application Access Mode
echo -e "${YELLOW}>> Access Mode Configuration${NC}"
if [[ "$USE_SSL" =~ ^[Yy]$ ]]; then
    echo "SSL is enabled. Nginx Reverse Proxy is REQUIRED."
    HAS_NGINX="true"
else
    echo "How should YADS be accessible?"
    echo "  1) Via Nginx Reverse Proxy (Recommended, allows port 80)"
    echo "  2) Direct API Access (Port $API_PORT directly to container)"
    read -p "Choose [1/2, default 1]: " ACCESS_CHOICE
    ACCESS_CHOICE=${ACCESS_CHOICE:-1}
    if [ "$ACCESS_CHOICE" == "1" ]; then
        HAS_NGINX="true"
    else
        HAS_NGINX="false"
    fi
fi

# 6. Generate Configurations
echo -e "${YELLOW}>> Generating Configurations...${NC}"

# Update .env with access mode
{
    echo "HAS_NGINX=$HAS_NGINX"
} >> .env

if [ "$HAS_NGINX" == "true" ]; then
    mkdir -p nginx
    sed "s/{{PORT}}/$API_PORT/g" nginx.conf.template > nginx/nginx.conf
    
    if [[ "$USE_SSL" =~ ^[Yy]$ ]]; then
        sed -i "/listen $API_PORT;/a \    ssl_certificate /etc/nginx/certs/yads.crt;\n    ssl_certificate_key /etc/nginx/certs/yads.key;" nginx/nginx.conf
        sed -i "s/listen $API_PORT;/listen $API_PORT ssl;/g" nginx/nginx.conf
    fi
    echo -e "${GREEN}✓ nginx/nginx.conf created${NC}"
else
    echo -e "${BLUE}Notice: No Nginx configuration genenerated. API will be exposed directly on port $API_PORT.${NC}"
fi

# 7. Final Steps
echo -e "${BLUE}==============================================================================${NC}"
echo -e "${GREEN}Configuration Complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Review the generated .env file"
if [ "$HAS_NGINX" == "true" ]; then
    echo "  2. Access YADS at: ${BLUE}http${USE_SSL:+s}://localhost:$API_PORT${NC}"
else
    echo "  2. Access YADS at: ${BLUE}http://localhost:$API_PORT${NC} (Direct API)"
fi
echo "  3. Start YADS with: ${BLUE}docker compose up -d${NC}"
echo ""
echo -e "${BLUE}==============================================================================${NC}"
