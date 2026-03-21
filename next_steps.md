# YADS OSINT Evolution: Technical Roadmap & Next Steps

This document serves as the high-level technical requirements and execution plan for evolving YADS from a basic scanner into a comprehensive Open Source Intelligence (OSINT) platform.

## 🎯 Global Objective
Transform YADS into a proactive intelligence platform that provides deep context (Identity, History, Leaks, Relationships) alongside traditional attack surface scanning.

---

## 🏗️ Implementation Strategy: "Module-First Enhancement"
- **Logic**: Implement 80% of OSINT features as standalone modules in `yads/modules/`.
- **Infrastructure**: Update core `models.py`, `api/`, and frontend ONLY to support the new modular data.
- **Backwards Compatibility**: Ensure the core scanner remains operational without OSINT API keys.

---

## 📅 Roadmap: 4-Phase Execution

### Phase 1: Identity & Enrichment (High Priority)
1. **Breach Monitoring**:
    - Update `yads/modules/leaked_credentials.py` to correctly handle HaveIBeenPwned and DeHashed API responses.
    - Implement a "Breached Identity" record in the database.
2. **Metadata Intelligence**:
    - Enable `yads/modules/metadata_scanner.py`.
    - Extract usernames, software versions, and network paths from public PDFs/Images.
3. **API Keys**: Add `HIBP_API_KEY` and `DEHASHED_API_KEY` to the System Config settings.

### Phase 2: Historical Context & Passive Recon
1. **Passive DNS**:
    - Implement `historical_dns_analyzer.py` module.
    - Integrate with SecurityTrails/PassiveTotal to uncover decommissioned but still vulnerable subdomains.
2. **WHOIS Archives**:
    - Implement `whois_history_scanner.py` to identify original registrants and corporate relationships.

### Phase 3: Deep Web & Social Surface
1. **Secret Leak Detection**:
    - Create `leak_monitor.py` to scan public GitHub repos and Pastebin sites for domain references, API keys, and internal DB strings.
2. **Technical Footprint**:
    - Implement `tech_stack_analyzer.py` to correlate discovered technologies with public developer discussions (StackOverflow/GitHub).

### Phase 4: Visual Intelligence (Enterprise Visualization)
1. **Relationship Graph**:
    - Implement a graph-based UI (e.g., Cytoscape.js or Force Graph) to visualize connections between IPs, Domains, Breaches, and People.
    - Create a dedicated `GET /api/targets/{id}/intelligence-graph` endpoint.
2. **Asset Timeline**:
    - Build a chronological "History of Changes" view for every target to track infrastructure drift.

---

## 💻 Tech Tasks for the Coding Agent

### 1. Data Layer (`yads/models.py`)
- Define `OSINTIntelligence` model:
    - `id`, `target_id`, `module_name`, `data_type`, `data_json`, `severity`, `timestamp`.
- Link to traditional `Finding` model where appropriate.

### 2. API Layer (`yads/api/routers/osint.py`)
- Create routes to serve aggregated OSINT reports:
    - `GET /osint/target/{id}`: Returns latest intelligence for a specific target.
    - `POST /osint/refresh/{id}`: Triggers immediate OSINT-only scan.

### 3. Worker Orchestration (`yads/worker_tasks.py`)
- Create a new Celery task `run_osint_enrichment`.
- Integrate `leaked_credentials`, `metadata_scanner`, and `dns_history_scanner` into the high-priority queue.

---

## 🏁 Success Criteria
- [ ] Functional breach monitoring with dashboard alerts.
- [ ] Searchable historical DNS/WHOIS records.
- [ ] Interactive graph showing asset relationships.
- [ ] Zero impact on the speed of the "Simple" port/vuln scan.
