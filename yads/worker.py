"""
worker.py — Thin shim for backwards compatibility.

All logic has been split into:
  - worker_core.py    : Celery app, signals, global state, helpers
  - worker_modules.py : LogCapture, _run_parallel_module, _run_simple_module
  - worker_tasks.py   : Celery task definitions (run_all_scans, etc.)

Existing imports like `from yads.worker import celery_app` continue to work.
"""
# Re-export everything that external code imports from this module
from yads.worker_core import (  # noqa: F401
    celery_app,
    _worker_client,
    logger,
    _reset_target_status,
    _patch_requests_with_throttling,
)
from yads.worker_modules import (  # noqa: F401
    LogCapture,
    _run_parallel_module,
    _run_simple_module,
)
from yads.worker_tasks import (  # noqa: F401
    run_all_scans,
    auto_dns_cleanup,
    calculate_security_trends,
    calculate_compliance_trends,
)
