#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# YADS Test Runner
# Wraps `make test` with optional dana testlab deployment.
#
# Usage:
#   ./scripts/run-tests.sh                      — full suite
#   ./scripts/run-tests.sh -m smoke             — smoke tests only
#   ./scripts/run-tests.sh -k test_login        — single test
#   DANA_DEPLOY=1 ./scripts/run-tests.sh        — also deploy testlab to dana
#
# Dana env vars (used when DANA_DEPLOY=1):
#   DANA_HOST   (default: dana)
#   DANA_USER   (default: root)
#   DANA_PORT   (default: 22)
#   DANA_PATH   (default: ~/yads-testenv)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

step() { echo -e "\n${GREEN}▶ $1${NC}"; }
warn() { echo -e "${YELLOW}⚠  $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; exit 1; }

# ── (Optional) Deploy testlab to dana ────────────────────────────────────────
if [[ "${DANA_DEPLOY:-0}" == "1" ]]; then
    DANA_HOST="${DANA_HOST:-dana}"
    DANA_USER="${DANA_USER:-root}"
    DANA_PORT="${DANA_PORT:-22}"
    DANA_PATH="${DANA_PATH:-~/yads-testenv}"

    step "Deploying testlab to $DANA_USER@$DANA_HOST:$DANA_PATH ..."
    ssh -o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
        -p "$DANA_PORT" "$DANA_USER@$DANA_HOST" "mkdir -p $DANA_PATH"

    rsync -avz --progress \
        -e "ssh -p $DANA_PORT -o StrictHostKeyChecking=accept-new" \
        docker-compose.testlab.yml \
        "$DANA_USER@$DANA_HOST:$DANA_PATH/"

    if [[ -d testlab ]]; then
        rsync -avz --progress \
            -e "ssh -p $DANA_PORT -o StrictHostKeyChecking=accept-new" \
            testlab/ "$DANA_USER@$DANA_HOST:$DANA_PATH/testlab/"
    fi

    ssh -p "$DANA_PORT" "$DANA_USER@$DANA_HOST" \
        "cd $DANA_PATH && docker compose -f docker-compose.testlab.yml pull --quiet && \
         docker compose -f docker-compose.testlab.yml up -d --remove-orphans"
    echo "Testlab deployed and started on dana."
fi

# ── Run tests ─────────────────────────────────────────────────────────────────
step "Running YADS test suite..."

# Pass remaining arguments as PYTEST_ARGS
PYTEST_ARGS="$*" docker compose -f docker-compose.test.yml run --rm test-runner
EXIT_CODE=$?

echo ""
if [[ $EXIT_CODE -eq 0 ]]; then
    echo -e "${GREEN}✅ All tests passed.${NC}"
else
    echo -e "${RED}✗ Tests failed (exit $EXIT_CODE).${NC}"
fi

exit $EXIT_CODE
