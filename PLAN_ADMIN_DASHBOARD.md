# Implementation Plan: System Administration Dashboard & Storage Analysis

## Overview

Two new features for YADS platform administration:
1. **System Administration Dashboard** - Central overview of workers, tasks, queue depth, and real-time resource metrics
2. **Storage Analysis** - Disk usage monitoring for screenshots and scan artifacts with cleanup recommendations

---

## Feature 1: System Administration Dashboard

### 1.1 Architecture

**New Files to Create:**

| File | Purpose |
|------|---------|
| `yads/api/routers/admin_dashboard.py` | API endpoints for dashboard data |
| `yads/api/templates/admin_dashboard.html` | Main dashboard template |
| `yads/api/templates/partials/_worker_card.html` | Reusable worker status card |
| `yads/api/templates/partials/_queue_stats.html` | Queue statistics partial |
| `yads/api/templates/partials/_resource_metrics.html` | Resource metrics partial |
| `yads/core/system_metrics.py` | System metrics collection utilities |

**Files to Modify:**

| File | Changes |
|------|---------|
| `yads/api/main.py` | Register new admin_dashboard router |
| `yads/api/templates/base.html` | Add sidebar link to Admin Dashboard |
| `yads/core/worker_manager.py` | Add enhanced metrics methods |

### 1.2 Dashboard Components

#### Component 1: Cluster Overview Card
```
┌─────────────────────────────────────────────────────────────┐
│  CLUSTER OVERVIEW                                           │
├─────────────┬─────────────┬─────────────┬─────────────────-─┤
│  Workers    │  Capacity   │  Queue      │  Utilization     │
│  4/5 Active │  16 Tasks   │  23 Pending │  ████████░░ 78%  │
└─────────────┴─────────────┴─────────────┴──────────────────-┘
```

**Data Source:** `WorkerManager.get_cluster_stats()` (existing)

#### Component 2: Worker Grid
```
┌─────────────────────────────────────────────────────────────┐
│  WORKERS                                        [Refresh]   │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐  │
│  │ ● worker-01     │  │ ● worker-02     │  │ ○ worker-03 │  │
│  │ 192.168.1.10    │  │ 192.168.1.11    │  │ OFFLINE     │  │
│  │ CPU: 45% RAM:2G │  │ CPU: 72% RAM:3G │  │ Last: 5m ago│  │
│  │ Tasks: 3/4      │  │ Tasks: 4/4      │  │ Tasks: 0/4  │  │
│  │ [Drain][Suspend]│  │ [Drain][Suspend]│  │ [Remove]    │  │
│  └─────────────────┘  └─────────────────┘  └─────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Data Source:** `WorkerManager.get_worker_list()` (existing) + enhanced metrics

#### Component 3: Active Tasks Table
```
┌─────────────────────────────────────────────────────────────┐
│  ACTIVE TASKS                                               │
├──────────┬────────────────┬──────────┬──────────┬──────────┤
│ Task ID  │ Domain         │ Worker   │ Module   │ Duration │
├──────────┼────────────────┼──────────┼──────────┼──────────┤
│ abc123   │ example.com    │ worker-01│ dns_scan │ 00:02:34 │
│ def456   │ test.org       │ worker-02│ nuclei   │ 00:15:22 │
└──────────┴────────────────┴──────────┴──────────┴──────────┘
```

**Data Source:** `WorkerTask` model with status='running'

#### Component 4: Queue Depth Chart
```
┌─────────────────────────────────────────────────────────────┐
│  QUEUE DEPTH (Last 1 Hour)                                  │
│                                                             │
│  25 ┤                    ╭─╮                                │
│  20 ┤              ╭─────╯ ╰──╮                             │
│  15 ┤         ╭────╯          ╰───╮                         │
│  10 ┤    ╭────╯                    ╰────                    │
│   5 ┤────╯                                                  │
│   0 ┼────────────────────────────────────────────           │
│     00:00   00:15   00:30   00:45   01:00                   │
└─────────────────────────────────────────────────────────────┘
```

**Data Source:** New - requires queue depth history tracking in Redis

#### Component 5: Resource Metrics (Real-Time)
```
┌─────────────────────────────────────────────────────────────┐
│  SYSTEM RESOURCES                              [Auto: 10s]  │
├─────────────────────────────────────────────────────────────┤
│  CPU Usage          RAM Usage           Network I/O         │
│  ████████░░ 78%     ██████░░░░ 62%      ↓ 12.3 MB/s        │
│                                         ↑ 4.7 MB/s          │
│  Per-Worker Breakdown:                                      │
│  worker-01: CPU 45% | RAM 2.1GB | Net: 5.2 MB/s            │
│  worker-02: CPU 72% | RAM 3.4GB | Net: 8.1 MB/s            │
└─────────────────────────────────────────────────────────────┘
```

**Data Source:** New - worker heartbeat must include CPU/RAM metrics

### 1.3 API Endpoints

```python
# yads/api/routers/admin_dashboard.py

@router.get("/")
async def admin_dashboard_page()
    """Main dashboard page (HTML)"""

@router.get("/api/cluster-stats")
async def get_cluster_stats()
    """Returns cluster overview JSON"""
    # Uses existing WorkerManager.get_cluster_stats()

@router.get("/api/workers")
async def get_workers_status()
    """Returns all workers with metrics JSON"""
    # Enhanced version with CPU/RAM

@router.get("/api/active-tasks")
async def get_active_tasks()
    """Returns currently running tasks"""
    # Query WorkerTask where status='running'

@router.get("/api/queue-depth")
async def get_queue_depth()
    """Returns queue depth metrics"""
    # Celery inspector + Redis queue length

@router.get("/api/queue-history")
async def get_queue_history(hours: int = 1)
    """Returns queue depth history for charting"""
    # New Redis time-series data

@router.post("/api/workers/{node_id}/action")
async def worker_action(node_id: str, action: str)
    """Suspend/Resume/Drain/Remove worker"""
    # Existing functionality, consolidated endpoint
```

### 1.4 Enhanced Worker Heartbeat

**Modify `yads/core/worker_client.py`:**

```python
def _collect_system_metrics(self) -> Dict[str, Any]:
    """Collect real-time system metrics for heartbeat."""
    import psutil

    return {
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_used_mb": psutil.virtual_memory().used // (1024 * 1024),
        "memory_total_mb": psutil.virtual_memory().total // (1024 * 1024),
        "disk_used_percent": psutil.disk_usage('/').percent,
        "network_bytes_sent": psutil.net_io_counters().bytes_sent,
        "network_bytes_recv": psutil.net_io_counters().bytes_recv,
    }
```

**Modify `WorkerNode` model:**

```python
# Add to yads/models.py
cpu_percent: float = Field(default=0.0)
memory_used_mb: int = Field(default=0)
memory_total_mb: int = Field(default=0)
disk_used_percent: float = Field(default=0.0)
network_bytes_sent: int = Field(default=0)
network_bytes_recv: int = Field(default=0)
last_metrics_at: Optional[datetime] = None
```

### 1.5 Queue Depth History

**New Redis Keys:**

```python
# Store queue depth every minute
QUEUE_DEPTH_KEY = "admin:queue_depth:history"  # Sorted set by timestamp

# Store in periodic task (every 60 seconds)
def record_queue_depth():
    depth = len(celery_app.control.inspect().reserved() or {})
    redis.zadd(QUEUE_DEPTH_KEY, {f"{timestamp}:{depth}": timestamp})
    # Keep only last 24 hours
    redis.zremrangebyscore(QUEUE_DEPTH_KEY, 0, timestamp - 86400)
```

### 1.6 Frontend Implementation

**Auto-Refresh with HTMX:**

```html
<!-- Cluster stats - refresh every 10 seconds -->
<div hx-get="/admin/api/cluster-stats"
     hx-trigger="every 10s"
     hx-swap="innerHTML">
    {% include 'partials/_cluster_stats.html' %}
</div>

<!-- Worker grid - refresh every 15 seconds -->
<div hx-get="/admin/api/workers"
     hx-trigger="every 15s"
     hx-swap="innerHTML">
    {% include 'partials/_worker_grid.html' %}
</div>

<!-- Active tasks - refresh every 5 seconds -->
<div hx-get="/admin/api/active-tasks"
     hx-trigger="every 5s"
     hx-swap="innerHTML">
    {% include 'partials/_active_tasks.html' %}
</div>
```

**Chart.js for Queue Depth:**

```javascript
// Queue depth line chart
const ctx = document.getElementById('queueChart').getContext('2d');
const queueChart = new Chart(ctx, {
    type: 'line',
    data: { /* from /api/queue-history */ },
    options: {
        responsive: true,
        scales: { y: { beginAtZero: true } }
    }
});

// Auto-update every 60 seconds
setInterval(async () => {
    const data = await fetch('/admin/api/queue-history').then(r => r.json());
    queueChart.data = data;
    queueChart.update();
}, 60000);
```

---

## Feature 2: Storage Analysis

### 2.1 Architecture

**New Files to Create:**

| File | Purpose |
|------|---------|
| `yads/core/storage_analyzer.py` | Storage analysis and cleanup utilities |
| `yads/api/routers/storage.py` | API endpoints for storage management |
| `yads/api/templates/storage_analysis.html` | Storage dashboard template |
| `yads/api/templates/partials/_storage_breakdown.html` | Storage breakdown partial |

### 2.2 Storage Analysis Components

#### Component 1: Storage Overview
```
┌─────────────────────────────────────────────────────────────┐
│  STORAGE OVERVIEW                                           │
├─────────────────────────────────────────────────────────────┤
│  Screenshots      Scan Artifacts     Database      Logs     │
│  ██████████ 75MB  ████░░░░░░ 12MB    ███████ 156MB ██ 8MB  │
│  6,100 files      1,200 files        14 tables     Redis   │
│                                                             │
│  Total: 251 MB    Available: 45.2 GB    Usage: 0.5%        │
└─────────────────────────────────────────────────────────────┘
```

#### Component 2: Screenshot Analysis
```
┌─────────────────────────────────────────────────────────────┐
│  SCREENSHOT STORAGE                           [Analyze Now] │
├─────────────────────────────────────────────────────────────┤
│  Directory: /app/yads/api/static/screenshots/               │
│  Total Size: 75.3 MB | Files: 6,127 | Oldest: 2024-01-15   │
│                                                             │
│  Age Distribution:                                          │
│  ├─ < 7 days:   1,234 files (15.2 MB) ████████░░           │
│  ├─ 7-30 days:  2,456 files (28.4 MB) ██████████████░░     │
│  ├─ 30-90 days: 1,892 files (22.1 MB) ███████████░░░       │
│  └─ > 90 days:    545 files (9.6 MB)  █████░░░░░░          │
│                                                             │
│  Top Domains by Size:                                       │
│  1. example.com     - 234 files - 8.2 MB                   │
│  2. test.org        - 189 files - 6.7 MB                   │
│  3. demo.io         - 156 files - 5.4 MB                   │
│                                                             │
│  Cleanup Recommendations:                                   │
│  ⚠ 545 files older than 90 days (9.6 MB) can be archived  │
│  ⚠ 23 orphaned files (no matching target) - 1.2 MB        │
│                                                             │
│  [Archive Old Files]  [Delete Orphans]  [Export Report]    │
└─────────────────────────────────────────────────────────────┘
```

#### Component 3: Database Storage
```
┌─────────────────────────────────────────────────────────────┐
│  DATABASE STORAGE                                           │
├─────────────────────────────────────────────────────────────┤
│  Table              Rows      Size      Index Size          │
│  ─────────────────────────────────────────────────────────  │
│  scanresult         45,234    98.2 MB   12.4 MB            │
│  httptraffic        12,456    34.5 MB   4.2 MB             │
│  target             1,234     2.1 MB    0.3 MB             │
│  modulestate        8,456     1.8 MB    0.4 MB             │
│  changeevent        3,234     0.9 MB    0.1 MB             │
│  ... (other tables)                                         │
│  ─────────────────────────────────────────────────────────  │
│  Total:                       156.2 MB  18.1 MB            │
│                                                             │
│  Recommendations:                                           │
│  ⚠ scanresult: 12,456 rows older than 180 days            │
│  ⚠ httptraffic: Consider archiving entries > 90 days      │
│                                                             │
│  [Vacuum Database]  [Archive Old Scans]  [Export Stats]    │
└─────────────────────────────────────────────────────────────┘
```

### 2.3 Storage Analyzer Class

```python
# yads/core/storage_analyzer.py

from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any
from dataclasses import dataclass

@dataclass
class FileStats:
    path: str
    size_bytes: int
    modified_at: datetime
    domain: Optional[str]

@dataclass
class StorageReport:
    total_size_bytes: int
    file_count: int
    oldest_file: datetime
    newest_file: datetime
    by_age: Dict[str, Dict]  # {"<7d": {"count": x, "size": y}, ...}
    by_domain: List[Dict]     # [{"domain": x, "count": y, "size": z}, ...]
    orphaned_files: List[FileStats]
    cleanup_recommendations: List[Dict]

class StorageAnalyzer:
    """Analyzes and manages storage for YADS artifacts."""

    SCREENSHOT_DIR = Path("yads/api/static/screenshots")
    LOCKED_DIR = Path("yads/api/static/screenshots_locked")

    def analyze_screenshots(self) -> StorageReport:
        """Analyze screenshot storage usage."""

    def analyze_database(self) -> Dict[str, Any]:
        """Get database table sizes and row counts."""

    def find_orphaned_screenshots(self, db_session) -> List[FileStats]:
        """Find screenshots with no matching target in database."""

    def get_cleanup_recommendations(self) -> List[Dict]:
        """Generate cleanup recommendations based on age and orphan status."""

    def archive_old_files(self, older_than_days: int = 90) -> Dict:
        """Move old files to archive directory."""

    def delete_orphaned_files(self, dry_run: bool = True) -> Dict:
        """Delete or report orphaned files."""

    def get_disk_usage(self) -> Dict[str, Any]:
        """Get overall disk usage statistics."""
```

### 2.4 API Endpoints

```python
# yads/api/routers/storage.py

@router.get("/")
async def storage_analysis_page()
    """Main storage analysis page (HTML)"""

@router.get("/api/overview")
async def get_storage_overview()
    """Returns storage overview JSON"""
    # Disk usage, category breakdown

@router.get("/api/screenshots")
async def get_screenshot_analysis()
    """Returns detailed screenshot analysis"""
    # Age distribution, top domains, orphans

@router.get("/api/database")
async def get_database_analysis()
    """Returns database storage analysis"""
    # Table sizes, row counts, recommendations

@router.get("/api/recommendations")
async def get_cleanup_recommendations()
    """Returns cleanup recommendations"""

@router.post("/api/cleanup/archive-old")
async def archive_old_files(older_than_days: int = 90)
    """Archive files older than specified days"""

@router.post("/api/cleanup/delete-orphans")
async def delete_orphaned_files(dry_run: bool = True)
    """Delete orphaned files (dry_run for preview)"""

@router.post("/api/cleanup/vacuum-db")
async def vacuum_database()
    """Run PostgreSQL VACUUM ANALYZE"""

@router.get("/api/export-report")
async def export_storage_report()
    """Export storage analysis as JSON/CSV"""
```

### 2.5 Database Size Query

```sql
-- Get table sizes in PostgreSQL
SELECT
    tablename AS table_name,
    pg_size_pretty(pg_total_relation_size(quote_ident(tablename))) AS total_size,
    pg_size_pretty(pg_relation_size(quote_ident(tablename))) AS table_size,
    pg_size_pretty(pg_indexes_size(quote_ident(tablename))) AS index_size,
    (SELECT count(*) FROM {tablename}) AS row_count
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(quote_ident(tablename)) DESC;
```

### 2.6 Cleanup Policies

**Screenshot Retention Policy:**

| Age | Action | Configurable |
|-----|--------|--------------|
| < 30 days | Keep | - |
| 30-90 days | Keep (warn) | Yes |
| > 90 days | Archive to ZIP | Yes |
| Orphaned | Delete after confirmation | Yes |

**Database Retention Policy:**

| Table | Retention | Action |
|-------|-----------|--------|
| scanresult | 180 days | Archive to backup, delete |
| httptraffic | 90 days | Delete (after backup) |
| changeevent | 365 days | Keep |
| securitytrend | Forever | Keep |

### 2.7 Configuration

**New SystemConfig Keys:**

```python
STORAGE_SCREENSHOT_RETENTION_DAYS = "90"      # Days before archival
STORAGE_SCANRESULT_RETENTION_DAYS = "180"     # Days before cleanup
STORAGE_HTTPTRAFFIC_RETENTION_DAYS = "90"     # Days before cleanup
STORAGE_AUTO_CLEANUP_ENABLED = "false"        # Enable automatic cleanup
STORAGE_CLEANUP_SCHEDULE = "0 3 * * 0"        # Weekly at 3 AM Sunday
```

---

## Database Changes

### New Model Fields (WorkerNode)

```python
# Add to yads/models.py - WorkerNode class
cpu_percent: float = Field(default=0.0)
memory_used_mb: int = Field(default=0)
memory_total_mb: int = Field(default=0)
disk_used_percent: float = Field(default=0.0)
network_bytes_sent: int = Field(default=0)
network_bytes_recv: int = Field(default=0)
last_metrics_at: Optional[datetime] = None
```

### Migration Script Addition

```sql
-- Add to scripts/maintenance/migrate_db.py

-- Worker metrics columns
ALTER TABLE workernode ADD COLUMN IF NOT EXISTS cpu_percent FLOAT DEFAULT 0.0;
ALTER TABLE workernode ADD COLUMN IF NOT EXISTS memory_used_mb INTEGER DEFAULT 0;
ALTER TABLE workernode ADD COLUMN IF NOT EXISTS memory_total_mb INTEGER DEFAULT 0;
ALTER TABLE workernode ADD COLUMN IF NOT EXISTS disk_used_percent FLOAT DEFAULT 0.0;
ALTER TABLE workernode ADD COLUMN IF NOT EXISTS network_bytes_sent BIGINT DEFAULT 0;
ALTER TABLE workernode ADD COLUMN IF NOT EXISTS network_bytes_recv BIGINT DEFAULT 0;
ALTER TABLE workernode ADD COLUMN IF NOT EXISTS last_metrics_at TIMESTAMP;
```

---

## Implementation Phases

### Phase 1: Infrastructure (Foundation)
1. Add WorkerNode metric fields to model
2. Create migration script
3. Implement `system_metrics.py` with psutil integration
4. Update worker heartbeat to include system metrics
5. Create `storage_analyzer.py` with basic analysis

### Phase 2: System Dashboard Backend
1. Create `admin_dashboard.py` router
2. Implement cluster stats endpoint (uses existing)
3. Implement enhanced worker list endpoint
4. Implement active tasks endpoint
5. Add queue depth history tracking in Redis
6. Add Celery beat task for periodic metrics collection

### Phase 3: System Dashboard Frontend
1. Create `admin_dashboard.html` template
2. Create partial templates for each component
3. Implement HTMX auto-refresh
4. Add Chart.js queue depth visualization
5. Add worker action buttons (suspend/resume/drain)
6. Add responsive grid layout

### Phase 4: Storage Analysis Backend
1. Create `storage.py` router
2. Implement screenshot analysis
3. Implement database size analysis
4. Implement orphan detection
5. Implement cleanup actions (archive/delete)

### Phase 5: Storage Analysis Frontend
1. Create `storage_analysis.html` template
2. Create storage breakdown visualizations
3. Add cleanup action buttons with confirmation
4. Add export functionality
5. Add dry-run preview for deletions

### Phase 6: Integration & Polish
1. Add sidebar navigation links
2. Add admin-only access control
3. Add toast notifications for actions
4. Add error handling
5. Add loading states
6. Documentation

---

## Dependencies

**New Python Packages:**

```
psutil>=5.9.0  # System metrics (CPU, RAM, disk, network)
```

**Existing (Already Installed):**
- Chart.js (via CDN in templates)
- HTMX (via CDN in templates)
- Redis (for queue depth history)

---

## Security Considerations

1. **Access Control**: All endpoints require `PlatformAdminChecker()` dependency
2. **Cleanup Confirmation**: Destructive actions require explicit confirmation
3. **Dry Run Mode**: Delete operations support dry_run preview
4. **Audit Logging**: All cleanup actions logged to Splunk
5. **Rate Limiting**: Cleanup operations throttled to prevent abuse

---

## UI/UX Patterns

1. **Auto-Refresh**: HTMX polling with configurable intervals
2. **Status Colors**: Green (healthy), Yellow (warning), Red (critical)
3. **Progress Indicators**: Loading spinners for async operations
4. **Confirmation Dialogs**: For destructive actions
5. **Toast Notifications**: Success/error feedback
6. **Responsive Design**: Grid layout adapts to screen size
7. **Dark Theme**: Consistent with existing YADS UI

---

## Testing Checklist

- [ ] Worker metrics collected correctly via heartbeat
- [ ] Dashboard loads with all components
- [ ] Auto-refresh works for all sections
- [ ] Queue depth chart renders correctly
- [ ] Worker actions (suspend/resume/drain) work
- [ ] Screenshot analysis accurately counts files
- [ ] Database size query returns correct values
- [ ] Orphan detection finds correct files
- [ ] Archive operation moves files correctly
- [ ] Delete operation removes files (with dry_run)
- [ ] Access control blocks non-admin users
- [ ] All cleanup actions logged

---

## Estimated File Sizes

| File | Lines (Est.) |
|------|--------------|
| `yads/core/system_metrics.py` | ~150 |
| `yads/core/storage_analyzer.py` | ~400 |
| `yads/api/routers/admin_dashboard.py` | ~300 |
| `yads/api/routers/storage.py` | ~250 |
| `yads/api/templates/admin_dashboard.html` | ~400 |
| `yads/api/templates/storage_analysis.html` | ~350 |
| Partials (4 files) | ~400 total |
| Migration additions | ~30 |
| **Total New Code** | **~2,280 lines** |
