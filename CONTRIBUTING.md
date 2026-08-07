# Contributing to yads

First off, thank you for considering contributing to `yads`! It's people like you that make open source such a great community.

## How can I contribute?

### Reporting Bugs
- Make sure you are on the latest version.
- Use the GitHub Issues tab to search if the bug has already been reported.
- If not, open a new issue. Include a clear description of the problem, steps to reproduce it, and any relevant logs (`docker logs yads-api` / `docker logs yads-worker`).

### Suggesting Enhancements
- Open a new issue with the label `enhancement`.
- Describe the current behavior and the new behavior you want to see.
- Explain why this enhancement would be useful to most users.

### Submitting Pull Requests
1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. Update the documentation (in `docs/` or `README.md`) if you change features or architecture.
4. Ensure your code follows the existing style and conventions.
5. Issue the pull request!

## Development Setup
yads is a FastAPI + Celery application. Local development runs it via Docker Compose from the sibling [`yads-infra`](https://github.com/MrMarco74/yads-infra) repo, which builds this repo's `api`/`worker` targets from source.
- To work on the API, check `yads/api/`.
- To work on scan/worker logic, check `yads/modules/` and `yads/core/`.
- To work on the frontend, check `frontend/`.

### Running locally
Clone `yads`, `yads-infra`, and (if you need breach-simulation) `yads-shadowtwin` as sibling directories, then from `yads-infra/`:
```bash
cp .env.example .env
# fill in secrets
docker compose -f docker-compose.yml up -d
```

### Running the test suite
```bash
make test          # full suite via docker compose (yads-infra/docker-compose.test.yml)
make test-fast      # or: make test-smoke / test-auth / test-targets / test-queue / test-users
make test-coverage  # with coverage report
```
See `requirements-test.txt` and `pytest.ini` for what's covered; `make test-run ARGS="-k test_login -s"` runs a filtered/custom pytest invocation.

## Project Philosophy

This codebase is built agentically (with Claude Code) and run as a hobby
project in the maintainer's spare time — there's no roadmap, SLA, or
guarantee that a given issue or pull request gets reviewed. Contributions
and reports are genuinely welcome, but they get acted on when they
happen to interest the maintainer, not on any particular schedule.
