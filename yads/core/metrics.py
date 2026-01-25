"""
Prometheus Metrics Module

Provides native Prometheus metrics for infrastructure monitoring.
Uses hybrid event-driven and polling collection strategy.

Usage:
    from yads.core.metrics import metrics

    # Record scan metrics
    metrics.record_scan_started(tenant_id=1, scan_types=["dns_scanner"])
    metrics.record_scan_completed(tenant_id=1, module_name="dns_scanner",
                                   duration_seconds=12.5, status="success")

    # Generate metrics for scraping
    output = metrics.generate_metrics()
"""

import logging
import time
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta

logger = logging.getLogger("yads.metrics")


class YADSMetrics:
    """
    Singleton metrics collector with lazy initialization.

    Follows the same pattern as SplunkHECLogger - graceful degradation
    when metrics are disabled or prometheus-client is not available.
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def initialize(self):
        """
        Lazy initialization to avoid import errors if prometheus-client
        is not installed and to defer config loading.
        """
        if self._initialized:
            return

        try:
            from yads.config import settings
            self.enabled = settings.METRICS_ENABLED
            self.include_tenant_labels = settings.METRICS_INCLUDE_TENANT_LABELS
            self.poll_interval = settings.METRICS_POLL_INTERVAL
        except Exception as e:
            logger.warning(f"Could not load metrics settings: {e}")
            self.enabled = False
            self.include_tenant_labels = False
            self.poll_interval = 30

        if not self.enabled:
            logger.info("Prometheus metrics disabled (METRICS_ENABLED=false)")
            self._initialized = True
            return

        try:
            from prometheus_client import (
                Counter, Gauge, Histogram, Info,
                CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
            )

            self._generate_latest = generate_latest
            self.CONTENT_TYPE = CONTENT_TYPE_LATEST

            # Create a custom registry to avoid conflicts with default metrics
            self._registry = CollectorRegistry()

            # Track last poll time for database metrics
            self._last_db_poll = None
            self._cached_db_metrics = {}

            # Setup all metrics
            self._setup_counters(Counter)
            self._setup_gauges(Gauge)
            self._setup_histograms(Histogram)
            self._setup_info(Info)

            logger.info("Prometheus metrics initialized successfully")

        except ImportError as e:
            logger.warning(f"prometheus-client not installed: {e}")
            self.enabled = False
        except Exception as e:
            logger.error(f"Failed to initialize Prometheus metrics: {e}")
            self.enabled = False

        self._initialized = True

    def _setup_counters(self, Counter):
        """Setup counter metrics."""
        # Scan counters
        if self.include_tenant_labels:
            self.scans_total = Counter(
                'yads_scans_total',
                'Total number of scans executed',
                ['tenant_id', 'module_name', 'status'],
                registry=self._registry
            )
        else:
            self.scans_total = Counter(
                'yads_scans_total',
                'Total number of scans executed',
                ['module_name', 'status'],
                registry=self._registry
            )

        # HTTP request counter
        self.http_requests_total = Counter(
            'yads_http_requests_total',
            'Total HTTP requests',
            ['method', 'path_template', 'status_code'],
            registry=self._registry
        )

        # Security events counter
        self.security_events_total = Counter(
            'yads_security_events_total',
            'Total security audit events',
            ['event_type', 'success'],
            registry=self._registry
        )

        # Scan errors counter
        if self.include_tenant_labels:
            self.scan_errors_total = Counter(
                'yads_scan_errors_total',
                'Total scan errors',
                ['tenant_id', 'module_name', 'error_type'],
                registry=self._registry
            )
        else:
            self.scan_errors_total = Counter(
                'yads_scan_errors_total',
                'Total scan errors',
                ['module_name', 'error_type'],
                registry=self._registry
            )

    def _setup_gauges(self, Gauge):
        """Setup gauge metrics."""
        # Active scans gauge
        if self.include_tenant_labels:
            self.active_scans = Gauge(
                'yads_active_scans',
                'Number of currently running scans',
                ['tenant_id'],
                registry=self._registry
            )
        else:
            self.active_scans = Gauge(
                'yads_active_scans',
                'Number of currently running scans',
                registry=self._registry
            )

        # Worker gauges
        self.workers_total = Gauge(
            'yads_workers_total',
            'Total number of workers by status',
            ['status'],
            registry=self._registry
        )

        self.queue_depth = Gauge(
            'yads_queue_depth',
            'Number of pending tasks in queue',
            registry=self._registry
        )

        # Target gauges
        if self.include_tenant_labels:
            self.targets_total = Gauge(
                'yads_targets_total',
                'Total number of targets',
                ['tenant_id', 'is_archived'],
                registry=self._registry
            )
        else:
            self.targets_total = Gauge(
                'yads_targets_total',
                'Total number of targets',
                ['is_archived'],
                registry=self._registry
            )

        # Worker utilization
        self.worker_utilization_percent = Gauge(
            'yads_worker_utilization_percent',
            'Overall worker cluster utilization percentage',
            registry=self._registry
        )

        # License status
        self.license_valid = Gauge(
            'yads_license_valid',
            'Whether the license is valid (1) or invalid/expired (0)',
            registry=self._registry
        )

        # Queue status
        self.queue_active = Gauge(
            'yads_queue_active',
            'Whether the queue is active (1) or paused (0)',
            registry=self._registry
        )

    def _setup_histograms(self, Histogram):
        """Setup histogram metrics."""
        # Scan duration histogram
        self.scan_duration_seconds = Histogram(
            'yads_scan_duration_seconds',
            'Scan duration in seconds',
            ['module_name'],
            buckets=[1, 5, 10, 30, 60, 120, 300, 600],
            registry=self._registry
        )

        # HTTP request duration histogram
        self.http_request_duration_seconds = Histogram(
            'yads_http_request_duration_seconds',
            'HTTP request duration in seconds',
            ['method', 'path_template'],
            buckets=[0.01, 0.05, 0.1, 0.5, 1, 5],
            registry=self._registry
        )

    def _setup_info(self, Info):
        """Setup info metrics."""
        self.yads_info = Info(
            'yads',
            'YADS application information',
            registry=self._registry
        )

        # Set initial info
        try:
            from yads.config import settings
            self.yads_info.info({
                'version': settings.VERSION,
                'project_name': settings.PROJECT_NAME
            })
        except Exception:
            self.yads_info.info({'version': 'unknown'})

    # =========================================================================
    # Recording Methods
    # =========================================================================

    def record_scan_started(self, tenant_id: Optional[int] = None,
                           scan_types: Optional[List[str]] = None):
        """Record that a scan has started."""
        if not self.enabled:
            return

        try:
            if self.include_tenant_labels:
                tenant_label = str(tenant_id) if tenant_id else "none"
                self.active_scans.labels(tenant_id=tenant_label).inc()
            else:
                self.active_scans.inc()
        except Exception as e:
            logger.warning(f"Failed to record scan_started metric: {e}")

    def record_scan_completed(self, tenant_id: Optional[int] = None,
                              module_name: str = "unknown",
                              duration_seconds: float = 0.0,
                              status: str = "success"):
        """Record that a scan module has completed."""
        if not self.enabled:
            return

        try:
            # Decrement active scans
            if self.include_tenant_labels:
                tenant_label = str(tenant_id) if tenant_id else "none"
                # Only decrement if this is the final module in a scan
                # (handled by record_scan_finished)

            # Record scan count
            if self.include_tenant_labels:
                tenant_label = str(tenant_id) if tenant_id else "none"
                self.scans_total.labels(
                    tenant_id=tenant_label,
                    module_name=module_name,
                    status=status
                ).inc()
            else:
                self.scans_total.labels(
                    module_name=module_name,
                    status=status
                ).inc()

            # Record duration
            self.scan_duration_seconds.labels(module_name=module_name).observe(duration_seconds)

        except Exception as e:
            logger.warning(f"Failed to record scan_completed metric: {e}")

    def record_scan_finished(self, tenant_id: Optional[int] = None):
        """Record that an entire scan job has finished (all modules done)."""
        if not self.enabled:
            return

        try:
            if self.include_tenant_labels:
                tenant_label = str(tenant_id) if tenant_id else "none"
                self.active_scans.labels(tenant_id=tenant_label).dec()
            else:
                self.active_scans.dec()
        except Exception as e:
            logger.warning(f"Failed to record scan_finished metric: {e}")

    def record_scan_error(self, tenant_id: Optional[int] = None,
                          module_name: str = "unknown",
                          error_type: str = "unknown"):
        """Record a scan error."""
        if not self.enabled:
            return

        try:
            if self.include_tenant_labels:
                tenant_label = str(tenant_id) if tenant_id else "none"
                self.scan_errors_total.labels(
                    tenant_id=tenant_label,
                    module_name=module_name,
                    error_type=error_type
                ).inc()
            else:
                self.scan_errors_total.labels(
                    module_name=module_name,
                    error_type=error_type
                ).inc()
        except Exception as e:
            logger.warning(f"Failed to record scan_error metric: {e}")

    def record_http_request(self, method: str, path_template: str,
                            status_code: int, duration_seconds: float):
        """Record an HTTP request."""
        if not self.enabled:
            return

        try:
            self.http_requests_total.labels(
                method=method,
                path_template=path_template,
                status_code=str(status_code)
            ).inc()

            self.http_request_duration_seconds.labels(
                method=method,
                path_template=path_template
            ).observe(duration_seconds)
        except Exception as e:
            logger.warning(f"Failed to record http_request metric: {e}")

    def record_security_event(self, event_type: str, success: bool = True):
        """Record a security audit event."""
        if not self.enabled:
            return

        try:
            self.security_events_total.labels(
                event_type=event_type,
                success=str(success).lower()
            ).inc()
        except Exception as e:
            logger.warning(f"Failed to record security_event metric: {e}")

    # =========================================================================
    # Database Metrics Collection (Polling)
    # =========================================================================

    def _should_poll_db(self) -> bool:
        """Check if enough time has passed since last DB poll."""
        if self._last_db_poll is None:
            return True

        elapsed = (datetime.utcnow() - self._last_db_poll).total_seconds()
        return elapsed >= self.poll_interval

    def _collect_database_metrics(self):
        """Collect metrics from database (cached with polling interval)."""
        if not self.enabled:
            return

        if not self._should_poll_db():
            return

        try:
            from sqlmodel import Session, select, func
            from yads.database import engine
            from yads.models import Target, WorkerNode, SystemConfig

            with Session(engine) as session:
                # Target counts
                self._collect_target_metrics(session, select, func, Target)

                # Worker metrics
                self._collect_worker_metrics(session, select, WorkerNode)

                # Queue metrics
                self._collect_queue_metrics(session, SystemConfig)

                # License status
                self._collect_license_metrics(session, SystemConfig)

            self._last_db_poll = datetime.utcnow()

        except Exception as e:
            logger.warning(f"Failed to collect database metrics: {e}")

    def _collect_target_metrics(self, session, select, func, Target):
        """Collect target count metrics."""
        try:
            if self.include_tenant_labels:
                # Group by tenant_id and is_archived
                query = select(
                    Target.tenant_id,
                    Target.is_archived,
                    func.count(Target.id)
                ).group_by(Target.tenant_id, Target.is_archived)

                results = session.exec(query).all()

                # Reset all to 0 first
                for tenant_id, is_archived, count in results:
                    tenant_label = str(tenant_id) if tenant_id else "none"
                    archived_label = "true" if is_archived else "false"
                    self.targets_total.labels(
                        tenant_id=tenant_label,
                        is_archived=archived_label
                    ).set(count)
            else:
                # Simple counts by is_archived
                active_count = session.exec(
                    select(func.count(Target.id)).where(Target.is_archived == False)
                ).one()
                archived_count = session.exec(
                    select(func.count(Target.id)).where(Target.is_archived == True)
                ).one()

                self.targets_total.labels(is_archived="false").set(active_count)
                self.targets_total.labels(is_archived="true").set(archived_count)

        except Exception as e:
            logger.debug(f"Failed to collect target metrics: {e}")

    def _collect_worker_metrics(self, session, select, WorkerNode):
        """Collect worker status metrics using WorkerManager snapshot."""
        try:
            from yads.core.worker_manager import worker_manager

            snapshot = worker_manager.get_metrics_snapshot()

            # Set worker counts by status
            workers_by_status = snapshot.get("workers_by_status", {})
            self.workers_total.labels(status="online").set(workers_by_status.get("online", 0))
            self.workers_total.labels(status="offline").set(workers_by_status.get("offline", 0))
            self.workers_total.labels(status="suspended").set(workers_by_status.get("suspended", 0))
            self.workers_total.labels(status="draining").set(workers_by_status.get("draining", 0))

            # Set utilization
            self.worker_utilization_percent.set(snapshot.get("utilization_percent", 0))

            # Set queue depth
            self.queue_depth.set(snapshot.get("queued_tasks", 0))

        except Exception as e:
            logger.debug(f"Failed to collect worker metrics: {e}")

    def _collect_queue_metrics(self, session, SystemConfig):
        """Collect queue status metrics."""
        try:
            # Queue active status
            config = session.get(SystemConfig, "QUEUE_ACTIVE")
            if config:
                is_active = config.value.lower() == "true"
                self.queue_active.set(1 if is_active else 0)
            else:
                self.queue_active.set(1)  # Default to active

            # Queue depth from Redis
            try:
                from yads.database import redis_client
                if redis_client:
                    queue_len = redis_client.llen("celery")
                    self.queue_depth.set(queue_len or 0)
            except Exception:
                pass

        except Exception as e:
            logger.debug(f"Failed to collect queue metrics: {e}")

    def _collect_license_metrics(self, session, SystemConfig):
        """Collect license status metrics."""
        try:
            from yads.core.license import license_manager

            config = session.get(SystemConfig, "license_key")
            if config and config.value:
                is_valid = license_manager.verify(config.value)
                self.license_valid.set(1 if is_valid else 0)
            else:
                self.license_valid.set(0)

        except Exception as e:
            logger.debug(f"Failed to collect license metrics: {e}")

    # =========================================================================
    # Output Generation
    # =========================================================================

    def generate_metrics(self) -> bytes:
        """
        Generate Prometheus text format output.

        Returns:
            bytes: Prometheus exposition format metrics
        """
        if not self.enabled:
            return b"# Metrics disabled\n"

        try:
            # Collect database metrics before generating output
            self._collect_database_metrics()

            return self._generate_latest(self._registry)
        except Exception as e:
            logger.error(f"Failed to generate metrics: {e}")
            return b"# Error generating metrics\n"


# Singleton instance (lazy initialized)
metrics = YADSMetrics()


def get_metrics() -> YADSMetrics:
    """Get the metrics singleton, ensuring it's initialized."""
    if not metrics._initialized:
        metrics.initialize()
    return metrics
