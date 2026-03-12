.PHONY: test test-build test-up test-down test-clean test-coverage \
        test-smoke test-auth test-targets test-queue test-users \
        test-fast help

COMPOSE_TEST = docker compose -f docker-compose.test.yml

# ── Full test run (build image if needed + run) ───────────────────────────────

test:
	$(COMPOSE_TEST) run --rm test-runner

test-build:
	$(COMPOSE_TEST) build test-runner

# ── Filtered runs ─────────────────────────────────────────────────────────────

test-smoke:
	PYTEST_ARGS="-m smoke" $(COMPOSE_TEST) run --rm test-runner

test-auth:
	PYTEST_ARGS="-m auth" $(COMPOSE_TEST) run --rm test-runner

test-targets:
	PYTEST_ARGS="-m targets" $(COMPOSE_TEST) run --rm test-runner

test-queue:
	PYTEST_ARGS="-m queue" $(COMPOSE_TEST) run --rm test-runner

test-users:
	PYTEST_ARGS="-m users" $(COMPOSE_TEST) run --rm test-runner

# pass custom pytest args: make test-run ARGS="-k test_login -s"
test-run:
	PYTEST_ARGS="$(ARGS)" $(COMPOSE_TEST) run --rm test-runner

# ── Coverage ──────────────────────────────────────────────────────────────────

test-coverage:
	PYTEST_ARGS="--cov=yads --cov-report=term-missing --cov-report=html:htmlcov" \
	    $(COMPOSE_TEST) run --rm test-runner
	@echo "Coverage report: htmlcov/index.html"

# ── Infrastructure helpers ────────────────────────────────────────────────────

test-up:
	$(COMPOSE_TEST) up -d test-db test-redis

test-down:
	$(COMPOSE_TEST) down

test-clean:
	$(COMPOSE_TEST) down -v
	@echo "Test volumes removed."

# ── Help ──────────────────────────────────────────────────────────────────────

help:
	@echo ""
	@echo "YADS Test Commands"
	@echo "══════════════════"
	@echo "  make test           Build + run full suite in Docker"
	@echo "  make test-build     Rebuild the test-runner image"
	@echo "  make test-smoke     Smoke tests only"
	@echo "  make test-auth      Auth tests only"
	@echo "  make test-targets   Target tests only"
	@echo "  make test-queue     Queue tests only"
	@echo "  make test-users     User tests only"
	@echo "  make test-coverage  HTML coverage report (htmlcov/)"
	@echo "  make test-clean     Stop + wipe test volumes"
	@echo ""
	@echo "  Custom args: make test-run ARGS='-k test_login -s'"
	@echo ""
