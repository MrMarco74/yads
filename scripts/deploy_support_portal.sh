#!/bin/bash
# =============================================================================
# deploy_support_portal.sh
#
# First-time deployment of the YADS Support Portal to PROD.
# Run from the repository root: bash scripts/deploy_support_portal.sh
#
# Steps performed:
#   1. Prompt for config (admin token, dashboard password, dry-run option)
#   2. Build Docker image locally
#   3. Issue TLS cert for support.yads-security.com (standalone — brief nginx outage)
#   4. Create Docker secrets (htpasswd)
#   5. Copy X25519 private key into support_keys volume
#   6. Transfer image + compose file to PROD
#   7. Update remote .env
#   8. docker stack deploy
#   9. Smoke test
# =============================================================================
set -euo pipefail

# --- Constants ---------------------------------------------------------------
REMOTE_HOST="root@prod.example.com"
STACK_NAME="yads"
REMOTE_DEPLOY_DIR="~/deploy/yads"
COMPOSE_FILE="docker-compose.swarm.yml"
NGINX_SERVICE="reverse-proxy-stack_reverse-proxy"
SUPPORT_IMAGE="registry.yads-security.com/yads-support:latest"
SUPPORT_IMAGE_ARCHIVE="yads_support_deploy.tgz"
SUPPORT_KEY_PATH="support/keys/dev_x25519_private.key"
DOMAIN="support.yads-security.com"
ADMIN_PUBLIC_KEY="lvbmCRtPXZ5Z6IDym34PyM+T6b/vh20AlZEOlIx6NgY="

# --- Colors ------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}>> $*${NC}"; }
success() { echo -e "${GREEN}✓  $*${NC}"; }
warn()    { echo -e "${YELLOW}⚠  $*${NC}"; }
die()     { echo -e "${RED}✗  $*${NC}"; exit 1; }

# =============================================================================
echo ""
echo "=============================================================================="
echo -e "${CYAN}  YADS Support Portal — First-Time Deployment${NC}"
echo "=============================================================================="
echo ""

# --- Preflight checks --------------------------------------------------------
[ -f "$SUPPORT_KEY_PATH" ] || die "X25519 private key not found at $SUPPORT_KEY_PATH — run: python3 scripts/generate_support_keypair.py"
[ -f "$COMPOSE_FILE" ] || die "docker-compose.swarm.yml not found. Run from repo root."
command -v docker &>/dev/null || die "docker not found"
command -v ssh &>/dev/null    || die "ssh not found"
command -v scp &>/dev/null    || die "scp not found"

# =============================================================================
# 1. Gather config
# =============================================================================
echo "--- Configuration ---"
echo ""

# Admin token
read -rp "SUPPORT_ADMIN_TOKEN (leave blank to auto-generate): " INPUT_ADMIN_TOKEN
if [ -z "$INPUT_ADMIN_TOKEN" ]; then
    ADMIN_TOKEN=$(openssl rand -hex 24)
    echo -e "  Generated: ${YELLOW}${ADMIN_TOKEN}${NC}"
    echo "  → Save this! You need it in the License Manager → Bug Report Keys page."
else
    ADMIN_TOKEN="$INPUT_ADMIN_TOKEN"
fi
echo ""

# Dashboard htpasswd
read -rp "Dashboard username [support]: " DASH_USER
DASH_USER="${DASH_USER:-support}"
read -rsp "Dashboard password: " DASH_PASS
echo ""
if [ -z "$DASH_PASS" ]; then
    die "Dashboard password cannot be empty."
fi

# IP allowlist
DEFAULT_IP="2a02:8071:63f1:10c0::/64,127.0.0.1"
read -rp "Admin IP allowlist [${DEFAULT_IP}]: " INPUT_IP_ALLOWLIST
ADMIN_IP_ALLOWLIST="${INPUT_IP_ALLOWLIST:-$DEFAULT_IP}"
echo ""

# Dry-run mode
read -rp "Dry run (print commands, don't execute)? [y/N]: " DRY_RUN
DRY_RUN="${DRY_RUN:-n}"

run() {
    if [[ "$DRY_RUN" =~ ^[Yy]$ ]]; then
        echo -e "  ${YELLOW}[DRY-RUN]${NC} $*"
    else
        eval "$@"
    fi
}

rssh() {
    if [[ "$DRY_RUN" =~ ^[Yy]$ ]]; then
        echo -e "  ${YELLOW}[DRY-RUN SSH]${NC} $*"
    else
        ssh "$REMOTE_HOST" "$@"
    fi
}

echo ""
echo "=============================================================================="
echo "Summary:"
echo "  Domain         : $DOMAIN"
echo "  Stack          : $STACK_NAME"
echo "  Remote         : $REMOTE_HOST"
echo "  Admin token    : ${ADMIN_TOKEN:0:8}…"
echo "  Dashboard user : $DASH_USER"
echo "  Admin IP allow : $ADMIN_IP_ALLOWLIST"
echo "  Admin pub key  : $ADMIN_PUBLIC_KEY"
echo "  Dry run        : $DRY_RUN"
echo "=============================================================================="
echo ""
read -rp "Proceed? [y/N]: " CONFIRM
[[ "$CONFIRM" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }
echo ""

# =============================================================================
# 2. Build Docker image
# =============================================================================
info "Building support portal Docker image..."
run "docker build -t '$SUPPORT_IMAGE' support/"
success "Image built: $SUPPORT_IMAGE"
echo ""

# =============================================================================
# 3. TLS certificate (standalone — brief nginx outage)
# =============================================================================
info "Checking if TLS cert for $DOMAIN already exists on PROD..."
CERT_EXISTS=$(ssh "$REMOTE_HOST" "[ -f /etc/letsencrypt/live/${DOMAIN}/fullchain.pem ] && echo yes || echo no" 2>/dev/null)

if [ "$CERT_EXISTS" = "yes" ]; then
    success "Certificate already exists — skipping."
else
    warn "Certificate NOT found. Will issue via standalone certbot (nginx will be down ~30s)."
    read -rp "  Continue? [y/N]: " CERT_CONFIRM
    [[ "$CERT_CONFIRM" =~ ^[Yy]$ ]] || die "Aborted at cert step."

    info "Scaling nginx to 0..."
    rssh "docker service scale $NGINX_SERVICE=0"

    info "Waiting for nginx to stop..."
    if [[ ! "$DRY_RUN" =~ ^[Yy]$ ]]; then
        for i in $(seq 1 15); do
            COUNT=$(ssh "$REMOTE_HOST" "docker ps -q --filter label=com.docker.swarm.service.name=$NGINX_SERVICE 2>/dev/null | wc -l")
            [ "$COUNT" -eq 0 ] && break
            echo "  waiting... ($i/15)"
            sleep 2
        done
    fi

    info "Issuing certificate with certbot standalone..."
    rssh "certbot certonly --standalone --cert-name '$DOMAIN' -d '$DOMAIN' \
        --email webmaster@highantdev.de --agree-tos --non-interactive"

    info "Fixing certificate permissions..."
    rssh "chmod -R 644 /etc/letsencrypt/live/$DOMAIN/ /etc/letsencrypt/archive/$DOMAIN/ && \
          chmod +x /etc/letsencrypt/live/$DOMAIN/ /etc/letsencrypt/archive/$DOMAIN/"

    info "Scaling nginx back to 1..."
    rssh "docker service scale $NGINX_SERVICE=1"
    success "Certificate issued for $DOMAIN"
fi
echo ""

# =============================================================================
# 4. Docker secrets
# =============================================================================
info "Creating support_htpasswd Docker secret..."

# Generate htpasswd entry (bcrypt)
if command -v htpasswd &>/dev/null; then
    HTPASSWD_ENTRY=$(htpasswd -nbB "$DASH_USER" "$DASH_PASS")
elif command -v openssl &>/dev/null; then
    # Fallback: apr1 md5 (less secure but universally available)
    HTPASSWD_ENTRY=$(openssl passwd -apr1 "$DASH_PASS" | xargs -I{} echo "$DASH_USER:{}")
else
    die "Neither htpasswd nor openssl found — cannot generate htpasswd entry."
fi

# Check if secret already exists
SECRET_EXISTS=$(ssh "$REMOTE_HOST" "docker secret ls --format '{{.Name}}' | grep -c '^support_htpasswd$'" 2>/dev/null || echo "0")
if [ "$SECRET_EXISTS" -gt 0 ]; then
    warn "Secret 'support_htpasswd' already exists."
    read -rp "  Remove and recreate? [y/N]: " RECREATE_SECRET
    if [[ "$RECREATE_SECRET" =~ ^[Yy]$ ]]; then
        rssh "docker secret rm support_htpasswd || true"
        if [[ ! "$DRY_RUN" =~ ^[Yy]$ ]]; then
            echo "$HTPASSWD_ENTRY" | ssh "$REMOTE_HOST" "docker secret create support_htpasswd -"
        else
            echo -e "  ${YELLOW}[DRY-RUN SSH]${NC} echo '<htpasswd>' | docker secret create support_htpasswd -"
        fi
        success "Secret 'support_htpasswd' recreated."
    else
        warn "Keeping existing secret."
    fi
else
    if [[ ! "$DRY_RUN" =~ ^[Yy]$ ]]; then
        echo "$HTPASSWD_ENTRY" | ssh "$REMOTE_HOST" "docker secret create support_htpasswd -"
    else
        echo -e "  ${YELLOW}[DRY-RUN SSH]${NC} echo '<htpasswd>' | docker secret create support_htpasswd -"
    fi
    success "Secret 'support_htpasswd' created."
fi
echo ""

# =============================================================================
# 5. Copy X25519 private key into support_keys volume
# =============================================================================
info "Copying X25519 private key to support_keys volume on PROD..."
# The portal expects raw 32-byte key material, base64-encoded (single line).
# If the key file is in PEM/PKCS8 format, extract the raw bytes first.
if grep -q "BEGIN PRIVATE KEY" "$SUPPORT_KEY_PATH" 2>/dev/null; then
    KEY_CONTENT=$(python3 -c "
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import base64, sys
pem = open('${SUPPORT_KEY_PATH}', 'rb').read()
key = load_pem_private_key(pem, password=None)
print(base64.b64encode(key.private_bytes_raw()).decode())
")
    info "  PEM key detected — extracted raw base64."
else
    KEY_CONTENT=$(cat "$SUPPORT_KEY_PATH")
fi
rssh "mkdir -p /tmp/support_key_init"
if [[ ! "$DRY_RUN" =~ ^[Yy]$ ]]; then
    # Write key to temp file on remote, then copy into a temp container
    ssh "$REMOTE_HOST" "echo '${KEY_CONTENT}' > /tmp/support_key_init/dev_x25519_private.key && chmod 600 /tmp/support_key_init/dev_x25519_private.key"
    # Create the volume if not exists
    ssh "$REMOTE_HOST" "docker volume create ${STACK_NAME}_support_keys 2>/dev/null || true"
    # Copy key into volume via a throwaway alpine container
    ssh "$REMOTE_HOST" "docker run --rm \
        -v ${STACK_NAME}_support_keys:/keys \
        -v /tmp/support_key_init:/src:ro \
        alpine sh -c 'cp /src/dev_x25519_private.key /keys/ && chmod 600 /keys/dev_x25519_private.key'"
    ssh "$REMOTE_HOST" "rm -rf /tmp/support_key_init"
else
    echo -e "  ${YELLOW}[DRY-RUN SSH]${NC} copy key → ${STACK_NAME}_support_keys volume"
fi
success "Private key copied to support_keys volume."
echo ""

# =============================================================================
# 6. Transfer image
# =============================================================================
info "Compressing support portal image..."
run "docker save '$SUPPORT_IMAGE' | gzip > '$SUPPORT_IMAGE_ARCHIVE'"

info "Transferring image to PROD ($(du -sh "$SUPPORT_IMAGE_ARCHIVE" 2>/dev/null | cut -f1))..."
run "scp '$SUPPORT_IMAGE_ARCHIVE' '$REMOTE_HOST:$REMOTE_DEPLOY_DIR/'"
run "rm -f '$SUPPORT_IMAGE_ARCHIVE'"

info "Loading image on PROD..."
rssh "gunzip -c $REMOTE_DEPLOY_DIR/$SUPPORT_IMAGE_ARCHIVE | docker load && rm -f $REMOTE_DEPLOY_DIR/$SUPPORT_IMAGE_ARCHIVE"
success "Image loaded on PROD."
echo ""

# =============================================================================
# 7. Transfer compose file + update .env
# =============================================================================
info "Uploading docker-compose.swarm.yml..."
run "scp '$COMPOSE_FILE' '$REMOTE_HOST:$REMOTE_DEPLOY_DIR/'"

info "Updating remote .env with support portal variables..."
set_env_var() {
    local key="$1"
    local val="$2"
    rssh "cd $REMOTE_DEPLOY_DIR && \
        if grep -q '^${key}=' .env 2>/dev/null; then \
            sed -i 's|^${key}=.*|${key}=${val}|' .env; \
        else \
            echo '${key}=${val}' >> .env; \
        fi"
}

set_env_var "SUPPORT_ADMIN_TOKEN" "$ADMIN_TOKEN"
set_env_var "SUPPORT_ADMIN_IP_ALLOWLIST" "$ADMIN_IP_ALLOWLIST"
set_env_var "SUPPORT_ADMIN_PUBLIC_KEY" "$ADMIN_PUBLIC_KEY"
success ".env updated."
echo ""

# =============================================================================
# 8. Stack deploy
# =============================================================================
info "Deploying stack..."
rssh "cd $REMOTE_DEPLOY_DIR && set -a && [ -f .env ] && source .env; set +a && \
    docker stack deploy -c $COMPOSE_FILE $STACK_NAME"
success "Stack deployed."
echo ""

# =============================================================================
# 9. Smoke test
# =============================================================================
info "Waiting 10s for service to start..."
if [[ ! "$DRY_RUN" =~ ^[Yy]$ ]]; then
    sleep 10
fi

info "Smoke test: POST /api/report (expect HTTP 422 = app is up)..."
if [[ ! "$DRY_RUN" =~ ^[Yy]$ ]]; then
    HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
        -X POST "https://$DOMAIN/api/report" \
        -H "Content-Type: application/json" \
        -d '{}' 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "422" ] || [ "$HTTP_CODE" = "200" ]; then
        success "Smoke test passed (HTTP $HTTP_CODE)"
    else
        warn "Unexpected HTTP $HTTP_CODE — check: ssh $REMOTE_HOST docker service logs ${STACK_NAME}_yads-support"
    fi
else
    echo -e "  ${YELLOW}[DRY-RUN]${NC} curl -sk https://$DOMAIN/api/report"
fi
echo ""

# =============================================================================
echo "=============================================================================="
echo -e "${GREEN}  Support Portal deployment complete!${NC}"
echo "=============================================================================="
echo ""
echo "  Dashboard: https://$DOMAIN"
echo "    User   : $DASH_USER"
echo "    Pass   : (as entered)"
echo ""
echo "  Admin API: https://$DOMAIN/api/admin/keys"
echo "    Token  : $ADMIN_TOKEN"
echo "    Pub key: $ADMIN_PUBLIC_KEY"
echo ""
echo "  → In License Manager: 'Bug Report Keys' → enter portal URL + admin token"
echo "    → 'Sync All to Portal' to register customer keys"
echo ""
echo "  Logs: ssh $REMOTE_HOST docker service logs ${STACK_NAME}_yads-support -f"
echo "=============================================================================="
