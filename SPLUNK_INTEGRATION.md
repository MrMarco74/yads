# YADS Splunk Integration & CIM Mapping Guide

This guide provides the Splunk configuration (`props.conf`), field extractions, and SPL queries for building SOC (MITRE ATT&CK) and Operations Dashboards.

---

## 1. Splunk Indexer / Heavy Forwarder Setup (`props.conf`)

Place the following configuration in `$SPLUNK_HOME/etc/apps/yads/default/props.conf` or `$SPLUNK_HOME/etc/system/local/props.conf`:

```ini
[yads:security]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_PREFIX = "time":
KV_MODE = json
TRUNCATE = 100000
category = Security
description = YADS Security Audit and Authentication Events

[yads:finding]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_PREFIX = "time":
KV_MODE = json
TRUNCATE = 100000
category = Vulnerability
description = YADS Vulnerability and Reconnaissance Findings

[yads:ops]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_PREFIX = "time":
KV_MODE = json
TRUNCATE = 100000
category = Operational
description = YADS System Health and Performance Events
```

---

## 2. Recommended SPL Search Queries for Splunk Dashboards

### A. SOC & MITRE ATT&CK Dashboard

#### 1. Real-time Threat & Recon Activity (Last 24h)
```splunk
index=* (sourcetype="yads:security" OR sourcetype="yads:finding")
| stats count by event.mitre_technique_id, event.action, event.domain, event.severity
| sort - count
```

#### 2. Critical & High Vulnerabilities Discovered (Nuclei & Open Ports)
```splunk
sourcetype="yads:finding" (event.severity="critical" OR event.severity="high")
| table _time, event.domain, event.finding_type, event.severity, event.mitre_technique_id, event.details.description
```

#### 3. Authentication & Audit Failures
```splunk
sourcetype="yads:security" event.details.success=false
| table _time, event.user, event.action, event.details.source_ip, event.details.user_agent
```

---

### B. IT-Operations & System Health Dashboard

#### 1. Scan Execution Durations (Performance Tracking)
```splunk
sourcetype="yads:ops" event.category="scan_completed"
| stats avg(event.details.duration_seconds) as avg_duration_sec, max(event.details.duration_seconds) as max_duration_sec, count by event.details.domain
| eval avg_duration_sec=round(avg_duration_sec, 2)
```

#### 2. Unhandled API & System Errors (HTTP 500 Tracking)
```splunk
sourcetype="yads:ops" event.category="api_error"
| table _time, event.details.method, event.details.url, event.details.error, event.details.traceback
```

#### 3. Event Traffic Volume by Sourcetype
```splunk
sourcetype="yads:*"
| timechart count by sourcetype
```
