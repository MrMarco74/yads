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
    POSTGRES_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=' | head -c 32)
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

# 5. Identity Provider (Keycloak)
echo -e "${YELLOW}>> Identity Provider (SSO/Keycloak)${NC}"
echo "YADS supports local user accounts (built-in) and SSO via Keycloak (OIDC)."
echo "  1) Local authentication only — no Keycloak needed (recommended for small teams)"
echo "  2) Bundled Keycloak — YADS manages a Keycloak instance via Docker"
echo "  3) External Keycloak — connect YADS to your existing Keycloak/OIDC server"
read -p "Choose [1/2/3, default 1]: " KC_CHOICE
KC_CHOICE=${KC_CHOICE:-1}

DOCKER_PROFILES=""
KC_ADMIN_PASSWORD=$(openssl rand -base64 16 | tr -d '/+=')
KC_DB_PASSWORD=$(openssl rand -base64 16 | tr -d '/+=')

case "$KC_CHOICE" in
    2)
        echo ""
        read -p "Keycloak port [default 8080]: " KC_PORT
        KC_PORT=${KC_PORT:-8080}
        read -p "YADS public hostname (e.g. yads.example.com or localhost) [default localhost]: " YADS_HOST
        YADS_HOST=${YADS_HOST:-localhost}
        DOCKER_PROFILES="keycloak"
        cat <<EOF >> .env

# --- Identity Provider (Bundled Keycloak) ---
AUTH_MODE=oidc
KC_PORT=$KC_PORT
KC_ADMIN=admin
KC_ADMIN_PASSWORD=$KC_ADMIN_PASSWORD
KC_DB_PASSWORD=$KC_DB_PASSWORD
OIDC_SERVER_URL=http://keycloak:8080
OIDC_PUBLIC_URL=http://${YADS_HOST}:${KC_PORT}
OIDC_REALM=yads
OIDC_CLIENT_ID=yads
OIDC_CLIENT_SECRET=$(openssl rand -hex 24)
OIDC_REDIRECT_URI=http://${YADS_HOST}:${API_PORT}/auth/oidc/callback
EOF
        echo -e "${GREEN}✓ Bundled Keycloak configured (port $KC_PORT)${NC}"
        echo -e "${BLUE}  Keycloak Admin: admin / $KC_ADMIN_PASSWORD${NC}"
        echo -e "${YELLOW}  Note: Run migration after first start:${NC}"
        echo -e "  docker exec yads-api python /app/scripts/maintenance/migrate_users_to_keycloak.py \\"
        echo -e "    --keycloak-url http://keycloak:8080"
        ;;
    3)
        echo ""
        read -p "Keycloak server URL (reachable from YADS container, e.g. https://keycloak.example.com): " EXT_KC_SERVER
        read -p "Keycloak public URL (browser-facing, often same as above): " EXT_KC_PUBLIC
        EXT_KC_PUBLIC=${EXT_KC_PUBLIC:-$EXT_KC_SERVER}
        read -p "Realm name: " EXT_KC_REALM
        read -p "Client ID [default yads]: " EXT_KC_CLIENT
        EXT_KC_CLIENT=${EXT_KC_CLIENT:-yads}
        read -p "Client Secret: " EXT_KC_SECRET
        read -p "YADS public hostname for redirect URI [default localhost]: " YADS_HOST
        YADS_HOST=${YADS_HOST:-localhost}
        cat <<EOF >> .env

# --- Identity Provider (External Keycloak/OIDC) ---
AUTH_MODE=oidc
OIDC_SERVER_URL=${EXT_KC_SERVER}
OIDC_PUBLIC_URL=${EXT_KC_PUBLIC}
OIDC_REALM=${EXT_KC_REALM}
OIDC_CLIENT_ID=${EXT_KC_CLIENT}
OIDC_CLIENT_SECRET=${EXT_KC_SECRET}
OIDC_REDIRECT_URI=http://${YADS_HOST}:${API_PORT}/auth/oidc/callback
EOF
        echo -e "${GREEN}✓ External Keycloak configured${NC}"
        echo -e "${YELLOW}  Note: Ensure YADS client exists in realm '${EXT_KC_REALM}' with:${NC}"
        echo -e "    - Redirect URI: http://${YADS_HOST}:${API_PORT}/auth/oidc/callback"
        echo -e "    - Protocol mappers: 'groups' (group-membership) + 'yads_tenant' (hardcoded)"
        ;;
    *)
        echo "AUTH_MODE=local" >> .env
        echo -e "${GREEN}✓ Local authentication selected (no Keycloak required)${NC}"
        ;;
esac
echo ""

# 6. Observability Stack (Prometheus/Grafana)
echo -e "${YELLOW}>> Observability & Monitoring${NC}"
echo "YADS exposes Prometheus metrics at /metrics for monitoring and alerting."
echo "  1) None — no monitoring stack"
echo "  2) Bundled stack — Prometheus + Grafana + Loki (managed by YADS Docker)"
echo "  3) External — connect your existing Prometheus/Grafana to YADS /metrics"
read -p "Choose [1/2/3, default 1]: " MON_CHOICE
MON_CHOICE=${MON_CHOICE:-1}

GRAFANA_ADMIN_PASSWORD=$(openssl rand -base64 16 | tr -d '/+=')
MINIO_PASSWORD=$(openssl rand -base64 16 | tr -d '/+=')
METRICS_TOKEN=$(openssl rand -hex 24)

case "$MON_CHOICE" in
    2)
        read -p "Grafana port [default 3000]: " GRAFANA_PORT
        GRAFANA_PORT=${GRAFANA_PORT:-3000}
        DOCKER_PROFILES="${DOCKER_PROFILES:+$DOCKER_PROFILES,}monitoring"
        cat <<EOF >> .env

# --- Observability Stack (Bundled) ---
METRICS_ENABLED=true
METRICS_AUTH_MODE=token
METRICS_TOKEN=$METRICS_TOKEN
GRAFANA_PORT=$GRAFANA_PORT
GRAFANA_ADMIN_PASSWORD=$GRAFANA_ADMIN_PASSWORD
MINIO_ROOT_PASSWORD=$MINIO_PASSWORD
EOF
        echo -e "${GREEN}✓ Bundled monitoring stack configured${NC}"
        echo -e "${BLUE}  Grafana: http://localhost:${GRAFANA_PORT} — admin / $GRAFANA_ADMIN_PASSWORD${NC}"
        ;;
    3)
        read -p "Your Prometheus scrape endpoint for YADS will be http://<host>:${API_PORT}/metrics"
        echo ""
        echo -e "${YELLOW}  Auth mode for /metrics endpoint:${NC}"
        echo "  1) None (open — only if Prometheus is on same host/network)"
        echo "  2) Bearer token (recommended)"
        read -p "Choose [1/2, default 2]: " METRICS_AUTH_CHOICE
        METRICS_AUTH_CHOICE=${METRICS_AUTH_CHOICE:-2}
        if [ "$METRICS_AUTH_CHOICE" == "1" ]; then
            METRICS_AUTH_STR="METRICS_AUTH_MODE=none"
        else
            METRICS_AUTH_STR="METRICS_AUTH_MODE=token
METRICS_TOKEN=$METRICS_TOKEN"
            echo -e "${BLUE}  Metrics token: $METRICS_TOKEN${NC}"
            echo -e "${YELLOW}  Add this to your Prometheus scrape config:${NC}"
            echo "    bearer_token: $METRICS_TOKEN"
        fi
        cat <<EOF >> .env

# --- Observability (External Prometheus/Grafana) ---
METRICS_ENABLED=true
$METRICS_AUTH_STR
EOF
        echo -e "${GREEN}✓ Metrics endpoint enabled for external Prometheus${NC}"
        ;;
    *)
        echo "# Monitoring: disabled" >> .env
        echo -e "${GREEN}✓ No monitoring stack configured${NC}"
        ;;
esac
echo ""

# Write Docker Compose profiles to .env if any optional stacks selected
if [ -n "$DOCKER_PROFILES" ]; then
    echo "COMPOSE_PROFILES=$DOCKER_PROFILES" >> .env
    echo -e "${BLUE}  Active Docker profiles: $DOCKER_PROFILES${NC}"
fi

# 7. Application Access Mode
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

# 8. Final Steps
echo -e "${BLUE}==============================================================================${NC}"
echo -e "${GREEN}Configuration Complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Review the generated .env file"
echo ""
if [ -n "$DOCKER_PROFILES" ]; then
    echo "  2. Start YADS (with optional stacks):"
    echo -e "     ${BLUE}docker compose up -d${NC}"
    echo -e "     ${YELLOW}(COMPOSE_PROFILES=$DOCKER_PROFILES is set in .env — optional services start automatically)${NC}"
else
    echo "  2. Start YADS:"
    echo -e "     ${BLUE}docker compose up -d${NC}"
fi
echo ""
if [ "$HAS_NGINX" == "true" ]; then
    echo "  3. Access YADS at: ${BLUE}http${USE_SSL:+s}://localhost:$API_PORT${NC}"
else
    echo "  3. Access YADS at: ${BLUE}http://localhost:$API_PORT${NC}"
fi
echo ""
if [ "$KC_CHOICE" == "2" ]; then
    echo "  4. Migrate existing users to Keycloak (after first start):"
    echo -e "     ${BLUE}docker exec yads-api python /app/scripts/maintenance/migrate_users_to_keycloak.py \\${NC}"
    echo -e "     ${BLUE}  --keycloak-url http://keycloak:8080 --dry-run${NC}"
    echo ""
fi
echo "  Manual override of optional stacks:"
echo "    Keycloak only:   docker compose --profile keycloak up -d"
echo "    Monitoring only: docker compose --profile monitoring up -d"
echo "    All stacks:      docker compose --profile keycloak --profile monitoring up -d"
echo ""
echo -e "${BLUE}==============================================================================${NC}"
