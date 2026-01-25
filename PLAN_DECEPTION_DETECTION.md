# Implementation Plan: Deception Technology Detection Module

## Overview

A new scanner module that identifies defensive deception infrastructure with confidence scoring. Each detection includes a **confidence score** (0-100) and **risk rating** (low/medium/high/critical) to help assess the target environment.

**Module Name:** `deception_detector`
**File:** `yads/modules/deception_detector.py`

---

## Architecture

### Return Schema

```python
{
    "honeypots": [
        {
            "type": str,              # "web", "ssh", "telnet", "smtp", "ftp", "generic"
            "indicator": str,         # What triggered detection
            "confidence": int,        # 0-100
            "risk_level": str,        # "low", "medium", "high", "critical"
            "port": int,              # Port where detected
            "details": {}             # Additional detection details
        }
    ],
    "sinkholes": [
        {
            "domain": str,            # The sinkholed domain
            "sinkhole_ip": str,       # IP it resolves to
            "sinkhole_operator": str, # "Spamhaus", "Microsoft", "FBI", etc.
            "confidence": int,
            "risk_level": str,
            "indicator": str
        }
    ],
    "tarpits": [
        {
            "type": str,              # "http", "smtp", "tcp"
            "port": int,
            "response_delay_ms": int, # Measured delay
            "confidence": int,
            "risk_level": str,
            "indicator": str
        }
    ],
    "summary": {
        "total_detections": int,
        "highest_confidence": int,
        "overall_risk": str,
        "deception_likelihood": str   # "none", "low", "moderate", "high", "certain"
    },
    "scanned_at": str
}
```

---

## Detection Capabilities

### 1. Honeypot Detection

#### 1.1 Web Honeypots

| Technique | Detection Method | Confidence Impact |
|-----------|------------------|-------------------|
| Glastopf signatures | Check for known Glastopf response patterns | +60 |
| SNARE/TANNER | Detect SNARE honeypot headers/responses | +70 |
| HoneyHTTPD | Known default pages and headers | +65 |
| Cowrie Web | Specific response patterns | +60 |
| Dionaea HTTP | Default Dionaea web module patterns | +55 |
| Generic low-interaction | Overly simple/static responses | +30 |
| Response timing anomalies | Too-fast or too-consistent response times | +20 |
| Missing expected headers | Absence of typical server headers | +15 |
| Fake vulnerability responses | Obviously fake "vulnerable" responses | +50 |

**Detection Indicators:**
- Known honeypot server headers (e.g., `Server: Apache/2.2.22 (Debian)` on Windows)
- Implausible technology combinations
- Known default honeypot HTML content hashes
- Response body containing honeypot signatures
- Unusual session/cookie patterns
- All responses returning same content regardless of path

#### 1.2 SSH Honeypots

| Technique | Detection Method | Confidence Impact |
|-----------|------------------|-------------------|
| Cowrie detection | Banner analysis, command response patterns | +70 |
| Kippo detection | Known Kippo banners and behaviors | +65 |
| HonSSH detection | Specific response characteristics | +60 |
| Banner mismatch | SSH version vs. behavior mismatch | +40 |
| Impossible OS/version | Banner claims impossible combination | +45 |
| Command response analysis | Run safe commands, analyze responses | +35 |

**Banner Signatures to Detect:**
```
SSH-2.0-OpenSSH_5.1p1 Debian-5  (Common Kippo default)
SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2 (Common Cowrie default)
```

#### 1.3 Service Honeypots (FTP, Telnet, SMTP)

| Service | Detection Method | Confidence Impact |
|---------|------------------|-------------------|
| FTP (Dionaea) | Known Dionaea FTP responses | +60 |
| Telnet (generic) | Too-permissive login, fake shell | +50 |
| SMTP (mailoney) | Unusual SMTP greeting, accepts all | +55 |
| Generic service | Implausible service behavior | +40 |

#### 1.4 Network/IDS Honeypots

| Technique | Detection Method | Confidence Impact |
|-----------|------------------|-------------------|
| HoneyD | Nmap OS fingerprint mismatch | +55 |
| Too many services | Unrealistic service count | +35 |
| Perfect uptime | Server never goes down | +15 |

### 2. DNS Sinkhole Detection

#### 2.1 Known Sinkhole IP Ranges

| Operator | IP Ranges/Patterns | Detection |
|----------|-------------------|-----------|
| Spamhaus | Known sinkhole IPs | Direct match |
| Microsoft DCU | Takedown infrastructure | ASN + pattern |
| FBI/DOJ | Law enforcement sinkholes | Known IPs |
| Shadowserver | Research sinkholes | Known ranges |
| Cloudflare | 0.0.0.0, 127.0.0.1 patterns | DNS response |
| ISP sinkholes | ISP-specific patterns | ASN analysis |

#### 2.2 Detection Techniques

| Technique | Method | Confidence Impact |
|-----------|--------|-------------------|
| Known sinkhole IP match | Compare resolved IP to sinkhole database | +90 |
| Shared IP for many domains | Same IP serves unrelated domains | +60 |
| Sinkhole ASN | IP belongs to known sinkhole operator | +70 |
| Generic landing page | Sinkhole notification page detection | +80 |
| NXDOMAIN to IP flip | Domain was NXDOMAIN, now resolves | +40 |
| Sudden IP change | Domain IP changed to known patterns | +50 |

#### 2.3 Sinkhole Operator Database

```python
SINKHOLE_OPERATORS = {
    "spamhaus": {
        "ips": ["127.0.0.2", "127.0.0.3", ...],
        "asn": ["AS30823"],
        "name": "Spamhaus"
    },
    "microsoft": {
        "patterns": ["sinkhole.msft.net"],
        "asn": ["AS8075"],
        "name": "Microsoft DCU"
    },
    "shadowserver": {
        "ips": [...],
        "name": "Shadowserver Foundation"
    },
    # ... more operators
}
```

### 3. Tarpit Detection

#### 3.1 HTTP Tarpits

| Technique | Detection Method | Confidence Impact |
|-----------|------------------|-------------------|
| Slow response start | TTFB > 10 seconds | +50 |
| Trickling data | Data sent byte-by-byte | +70 |
| Endless response | Response never completes | +80 |
| LaBrea-style | Known tarpit response patterns | +65 |
| Deliberate slowdown | Response time proportional to request | +55 |

#### 3.2 SMTP Tarpits

| Technique | Detection Method | Confidence Impact |
|-----------|------------------|-------------------|
| Slow greeting | SMTP banner takes > 5 seconds | +60 |
| Character-by-character | Data sent one char at a time | +75 |
| Infinite recipients | Accepts unlimited RCPT TO | +50 |

#### 3.3 TCP Tarpits

| Technique | Detection Method | Confidence Impact |
|-----------|------------------|-------------------|
| Connection hold | Connection accepted but no data | +55 |
| SYN delay | SYN-ACK significantly delayed | +40 |
| Window size games | Zero window advertisements | +60 |

---

## Implementation Phases

### Phase 1: Core Infrastructure

**Files to Create:**
- `yads/modules/deception_detector.py` - Main scanner module
- `yads/modules/deception/__init__.py` - Detection submodule package
- `yads/modules/deception/signatures.py` - Known honeypot signatures
- `yads/modules/deception/sinkholes.py` - Sinkhole database
- `yads/modules/deception/scoring.py` - Confidence/risk calculation

**Database Changes:**
- None required (uses existing ScanResult model)

**Integration Points:**
- `yads/worker.py` - Add execution block
- `yads/api/main.py` - Add to valid_types

### Phase 2: Honeypot Detection Engine

```python
class HoneypotDetector:
    """Detects various types of honeypots."""

    def detect_web_honeypot(self, url: str, response: Response) -> List[Detection]
    def detect_ssh_honeypot(self, host: str, port: int) -> List[Detection]
    def detect_service_honeypot(self, host: str, port: int, service: str) -> List[Detection]
    def analyze_banner(self, banner: str, service: str) -> List[Detection]
    def check_behavior_anomalies(self, responses: List[Response]) -> List[Detection]
```

**Key Detection Functions:**

1. **`_check_web_honeypot_signatures()`**
   - Match response against known honeypot HTML patterns
   - Check for known default pages (MD5/SHA256 hashes)
   - Analyze response headers for honeypot indicators

2. **`_check_ssh_banner()`**
   - Parse SSH banner for known honeypot versions
   - Detect impossible OS/version combinations
   - Check for Cowrie/Kippo default banners

3. **`_check_service_consistency()`**
   - Compare claimed service version with behavior
   - Detect implausible service combinations
   - Analyze timing patterns

### Phase 3: Sinkhole Detection Engine

```python
class SinkholeDetector:
    """Detects DNS sinkholes."""

    def check_known_sinkhole_ips(self, ip: str) -> Optional[Detection]
    def check_sinkhole_asn(self, ip: str) -> Optional[Detection]
    def detect_sinkhole_landing_page(self, response: Response) -> Optional[Detection]
    def analyze_dns_history(self, domain: str, current_ip: str) -> List[Detection]
```

**Sinkhole IP Database Structure:**
```python
# yads/modules/deception/sinkholes.py
SINKHOLE_IPS = {
    # Spamhaus DROP list indicators
    "127.0.0.2": {"operator": "Spamhaus", "type": "SBL", "confidence": 95},
    "127.0.0.3": {"operator": "Spamhaus", "type": "CSS", "confidence": 95},

    # Known Microsoft sinkholes
    "204.79.197.200": {"operator": "Microsoft DCU", "type": "takedown", "confidence": 90},

    # FBI/Law enforcement
    # ... (populated from public sources)

    # Research organizations
    # ...
}

SINKHOLE_ASNS = {
    "AS30823": "Spamhaus",
    "AS8075": "Microsoft",
    # ...
}

SINKHOLE_LANDING_PATTERNS = [
    r"This domain has been seized",
    r"sinkholed by",
    r"blocked by your ISP",
    r"malware.* blocked",
    # ...
]
```

### Phase 4: Tarpit Detection Engine

```python
class TarpitDetector:
    """Detects network tarpits."""

    def detect_http_tarpit(self, url: str) -> Optional[Detection]
    def detect_smtp_tarpit(self, host: str, port: int) -> Optional[Detection]
    def detect_tcp_tarpit(self, host: str, port: int) -> Optional[Detection]
    def measure_response_timing(self, host: str, port: int) -> TimingMetrics
```

**Timing Thresholds:**
```python
TARPIT_THRESHOLDS = {
    "http": {
        "ttfb_slow_ms": 10000,      # Time to first byte
        "trickle_rate_bps": 10,     # Bytes per second threshold
        "max_response_time_ms": 60000
    },
    "smtp": {
        "greeting_delay_ms": 5000,
        "per_char_delay_ms": 100
    },
    "tcp": {
        "connect_timeout_ms": 30000,
        "data_timeout_ms": 60000
    }
}
```

### Phase 5: Confidence Scoring System

```python
class DeceptionScorer:
    """Calculates confidence scores and risk levels."""

    def calculate_confidence(self, detections: List[Detection]) -> int:
        """Combine multiple indicators into overall confidence."""

    def calculate_risk_level(self, detection: Detection) -> str:
        """Determine risk level based on detection type and confidence."""

    def calculate_deception_likelihood(self, all_detections: List) -> str:
        """Overall assessment of deception presence."""
```

**Confidence Calculation Rules:**
```python
def calculate_confidence(self, detections: List[Detection]) -> int:
    """
    Combine detection confidences using weighted scoring.

    Rules:
    1. Start with highest single detection confidence
    2. Add diminishing returns for additional detections
    3. Cap at 99 (never 100% certain)
    4. Negative indicators can reduce confidence
    """
    if not detections:
        return 0

    sorted_detections = sorted(detections, key=lambda d: d.confidence, reverse=True)

    base = sorted_detections[0].confidence
    bonus = 0

    for i, d in enumerate(sorted_detections[1:], 1):
        # Diminishing returns: each additional detection adds less
        bonus += d.confidence * (0.5 ** i)

    return min(99, int(base + bonus))
```

**Risk Level Matrix:**

| Confidence | Detection Type | Risk Level |
|------------|----------------|------------|
| 80-100 | Honeypot | Critical |
| 60-79 | Honeypot | High |
| 40-59 | Honeypot | Medium |
| < 40 | Honeypot | Low |
| 80-100 | Sinkhole | High |
| 60-79 | Sinkhole | Medium |
| < 60 | Sinkhole | Low |
| 70-100 | Tarpit | High |
| 50-69 | Tarpit | Medium |
| < 50 | Tarpit | Low |

---

## Files to Modify

| File | Changes |
|------|---------|
| `yads/worker.py` | Add execution block for `deception_detector` |
| `yads/api/main.py` | Add `deception_detector` to `valid_types` |
| `yads/api/templates/target_detail.html` | Add deception detection results display |

---

## New Files to Create

| File | Purpose |
|------|---------|
| `yads/modules/deception_detector.py` | Main scanner module (DeceptionDetector class) |
| `yads/modules/deception/__init__.py` | Package init |
| `yads/modules/deception/honeypots.py` | HoneypotDetector class |
| `yads/modules/deception/sinkholes.py` | SinkholeDetector class + sinkhole database |
| `yads/modules/deception/tarpits.py` | TarpitDetector class |
| `yads/modules/deception/signatures.py` | Known signatures and patterns |
| `yads/modules/deception/scoring.py` | DeceptionScorer class |

---

## Dependencies

**No new dependencies required.** Uses existing:
- `requests` - HTTP requests
- `socket` - TCP connections
- `dns.resolver` - DNS lookups
- `concurrent.futures` - Parallel checks

**Optional enhancements:**
- `paramiko` - For deeper SSH analysis (already available)

---

## Rate Limiting & Safety

| Check Type | Rate Limit | Notes |
|------------|------------|-------|
| HTTP probes | 2 req/sec | Per target |
| SSH banner grab | 1 req/2sec | Avoid lockout |
| DNS lookups | 10 req/sec | Standard |
| TCP timing | 1 check/sec | Prevent detection |

**Safety Measures:**
1. Never send credentials or attempt authentication
2. Only perform passive/semi-passive detection
3. Limit connection attempts to avoid triggering alarms
4. Respect `robots.txt` for web honeypot detection
5. Log all detection attempts for audit

---

## UI Display Recommendations

### Target Detail Page Section

```html
<!-- Deception Detection Results -->
<div class="card">
    <h3>Deception Technology Detection</h3>

    <!-- Summary Banner -->
    <div class="alert alert-{{ risk_color }}">
        Deception Likelihood: {{ deception_likelihood }}
        ({{ total_detections }} indicators found)
    </div>

    <!-- Honeypots -->
    {% if honeypots %}
    <h4>Honeypots Detected</h4>
    <table>
        <tr>
            <th>Type</th>
            <th>Port</th>
            <th>Indicator</th>
            <th>Confidence</th>
            <th>Risk</th>
        </tr>
        {% for h in honeypots %}
        <tr>
            <td>{{ h.type }}</td>
            <td>{{ h.port }}</td>
            <td>{{ h.indicator }}</td>
            <td>{{ h.confidence }}%</td>
            <td><span class="badge badge-{{ h.risk_level }}">{{ h.risk_level }}</span></td>
        </tr>
        {% endfor %}
    </table>
    {% endif %}

    <!-- Similar sections for sinkholes and tarpits -->
</div>
```

---

## Testing Strategy

### Unit Tests
- Test each detection function with known honeypot responses
- Test confidence calculation with various input combinations
- Test sinkhole IP matching

### Integration Tests
- Set up local honeypot instances (Cowrie, Dionaea, etc.)
- Test against known public honeypots (HoneyDB samples)
- Verify no false positives on legitimate servers

### Test Targets (Safe)
- `honeypot.cert.org` - Research honeypot
- Known sinkhole IPs (read-only checks)
- Self-deployed test honeypots

---

## Implementation Order

1. **Week 1: Core Structure**
   - Create module skeleton
   - Implement signature database
   - Add worker/main.py integration

2. **Week 2: Honeypot Detection**
   - Web honeypot detection
   - SSH honeypot detection
   - Service honeypot detection

3. **Week 3: Sinkhole & Tarpit**
   - Sinkhole IP database
   - Sinkhole detection logic
   - Tarpit timing analysis

4. **Week 4: Scoring & UI**
   - Confidence scoring system
   - Risk level calculation
   - UI template updates
   - Testing and refinement

---

## Risk Considerations

| Risk | Mitigation |
|------|------------|
| False positives on CDNs | Whitelist known CDN patterns |
| Detection by honeypot operators | Use standard user agents, limit probes |
| Legal concerns | Only passive detection, no exploitation |
| Performance impact | Async checks, timeout limits |

---

## Future Enhancements (Out of Scope)

- Machine learning-based detection
- Historical deception tracking
- Honeypot fingerprint database updates
- Integration with threat intelligence feeds
- Active honeypot interaction analysis
