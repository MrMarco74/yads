from fpdf import FPDF
from typing import Dict, Any, List
import datetime
import io

def _s(text) -> str:
    """Sanitize text for Helvetica/Courier (ASCII-only). Replaces common Unicode punctuation."""
    return (
        str(text)
        .replace("\u2014", "-").replace("\u2013", "-")
        .replace("\u2026", "...").replace("\u00b7", "|")
        .replace("\u2018", "'").replace("\u2019", "'")
        .replace("\u201c", '"').replace("\u201d", '"')
        .replace("\u2022", "*")
        .encode("ascii", "replace").decode("ascii")
    )


def get_data(result):
    if hasattr(result, "data"):
        return result.data
    if isinstance(result, dict):
        return result.get("data")
    return None

class PDFReport(FPDF):
    def __init__(self, target: str):
        super().__init__()
        self.target = target
        self.set_auto_page_break(auto=True, margin=15)
        self.add_page()

    def header(self):
        # Logo or Title
        self.set_font('helvetica', 'B', 16)
        self.cell(0, 10, 'YADS Scan Report', border=False, new_x="LMARGIN", new_y="NEXT", align='L')
        self.set_font('helvetica', 'I', 10)
        self.cell(0, 5, f'Target: {self.target} | Date: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}', new_x="LMARGIN", new_y="NEXT", align='L')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', align='C')

    def chapter_title(self, title):
        self.set_font('helvetica', 'B', 14)
        self.set_fill_color(230, 230, 230)
        self.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT", fill=True)
        self.ln(4)

    def chapter_body(self, body):
        self.set_font('helvetica', '', 11)
        self.multi_cell(0, 5, body)
        self.ln()

    def add_section_dict(self, data: Dict[str, Any], indent=0):
        self.set_font('courier', '', 10)
        for k, v in data.items():
            self.set_x(self.l_margin + indent)
            if isinstance(v, (dict, list)):
                self._add_complex_item(k, v, indent)
            else:
                self.multi_cell(0, 5, f"{k}: {v}")

    def _add_complex_item(self, key: str, value: Any, indent: int):
        self.cell(0, 5, f"{key}:", new_x="LMARGIN", new_y="NEXT")
        if isinstance(value, dict):
            self.add_section_dict(value, indent + 5)
        elif isinstance(value, list):
            for item in value:
                self.set_x(self.l_margin + indent + 5)
                self.cell(0, 5, f"- {item}", new_x="LMARGIN", new_y="NEXT")

    def add_dns_section(self, result):
        self.chapter_title("DNS Analysis")
        data = get_data(result)
        if not data:
            self.chapter_body("No DNS data available.")
            return

        # Subdomains
        subdomains = data.get("subdomains", [])
        self.set_font('helvetica', 'B', 12)
        self.cell(0, 8, f"Subdomains Found: {len(subdomains)}", new_x="LMARGIN", new_y="NEXT")
        self.set_font('courier', '', 10)
        for sub in subdomains[:10]: # Limit to 10 for brevity in PDF
            self.cell(0, 5, f" - {sub['subdomain']} ({', '.join(sub['ips'])})", new_x="LMARGIN", new_y="NEXT")
        if len(subdomains) > 10:
             self.cell(0, 5, f" ... and {len(subdomains)-10} more.", new_x="LMARGIN", new_y="NEXT")
        self.ln()

        # Records
        records = data.get("records", {})
        self.set_font('helvetica', 'B', 12)
        self.cell(0, 8, "DNS Records", new_x="LMARGIN", new_y="NEXT")
        self.add_section_dict(records)
        self.ln()

    def add_infra_section(self, result):
        self.chapter_title("Infrastructure & Reputation")
        data = get_data(result)
        if not data:
            self.chapter_body("No Infrastructure data available.")
            return

        self.set_font('helvetica', 'B', 12)
        self.cell(0, 8, "Network Info", new_x="LMARGIN", new_y="NEXT")
        
        info = {
            "IP": data.get("ip"),
            "ASN": data.get("asn", {}).get("asn"),
            "Organization": data.get("asn", {}).get("asn_description"),
            "Country": data.get("asn", {}).get("country"),
            "Cloud Provider": data.get("cloud_provider"),
        }
        self.add_section_dict(info)
        self.ln()
        
        # Reputation
        reputation = data.get("reputation", [])
        if reputation:
             self.set_font('helvetica', 'B', 12)
             self.set_text_color(200, 0, 0)
             self.cell(0, 8, "Reputation Flags Detected!", new_x="LMARGIN", new_y="NEXT")
             self.set_text_color(0, 0, 0)
             self.set_font('courier', '', 10)
             for flag in reputation:
                 self.cell(0, 5, f" - {flag}", new_x="LMARGIN", new_y="NEXT")
             self.ln()

    def add_web_section(self, result):
        self.chapter_title("Web Analysis")
        data = get_data(result)
        if not data:
            self.chapter_body("No Web Analysis data available.")
            return
            
        self.set_font('helvetica', 'B', 12)
        self.cell(0, 8, f"Descriptive: {data.get('title')}", new_x="LMARGIN", new_y="NEXT")
        self.set_font('courier', '', 10)
        self.cell(0, 5, f"Status Code: {data.get('status_code')}", new_x="LMARGIN", new_y="NEXT")
        self.cell(0, 5, f"Server: {data.get('server')}", new_x="LMARGIN", new_y="NEXT")
        self.ln()
        
        # Tech Stack
        if data.get("tech_stack"):
            self.set_font('helvetica', 'B', 12)
            self.cell(0, 8, "Tech Stack", new_x="LMARGIN", new_y="NEXT")
            self.set_font('courier', '', 10)
            for tech in data["tech_stack"]:
                 self.cell(0, 5, f" - {tech}", new_x="LMARGIN", new_y="NEXT")
            self.ln()

        # Vulnerabilities (CVEs)
        cves = data.get("cves", [])
        if cves:
            self.set_font('helvetica', 'B', 12)
            self.set_text_color(200, 0, 0)
            self.cell(0, 8, f"Potential Vulnerabilities ({len(cves)})", new_x="LMARGIN", new_y="NEXT")
            self.set_text_color(0, 0, 0)
            self.set_font('courier', '', 10)
            for cve in cves:
                 self.cell(0, 5, f" [{cve['id']}] {cve.get('summary', '')[:80]}...", new_x="LMARGIN", new_y="NEXT")
            self.ln()

        # Risk Hints
        hints = data.get("risk_hints", [])
        if hints:
            self.set_font('helvetica', 'B', 12)
            self.cell(0, 8, "Risk Indicators", new_x="LMARGIN", new_y="NEXT")
            self.set_font('courier', '', 10)
            for hint in hints:
                 self.cell(0, 5, f" - {hint}", new_x="LMARGIN", new_y="NEXT")
            self.ln()

    def add_typosquat_section(self, result):
        self.chapter_title("Typosquatting")
        data = get_data(result)
        if not data:
            self.chapter_body("No Typosquatting data available.")
            return
            
        found = data.get("found", [])
        
        self.set_font('helvetica', '', 12)
        self.cell(0, 8, f"Scanned {data.get('scanned_count')} variations. Found {len(found)} active.", new_x="LMARGIN", new_y="NEXT")
        self.ln()
        
        if found:
            self.set_font('courier', '', 10)
            for item in found[:15]:
                self.cell(0, 5, f" - {item['domain']} ({item.get('ip')}) - {item.get('fuzzer')}", new_x="LMARGIN", new_y="NEXT")
            if len(found) > 15:
                 self.cell(0, 5, f" ... {len(found)-15} more", new_x="LMARGIN", new_y="NEXT")
            self.ln()

    def add_api_discovery_section(self, result):
        self.chapter_title("API Discovery")
        data = get_data(result)
        if not data:
            self.chapter_body("No API Discovery data available.")
            return

        self._add_api_sub_section(data, "definitions_found", "API Definitions Found")
        self._add_api_sub_section(data, "prefixes_found", "API Prefixes Discovered")
        self._add_api_list_sub_section(data, "endpoints", "Endpoints Extracted")

    def _add_api_sub_section(self, data, key, title):
        items = data.get(key, [])
        if not items: return
        self.set_font('helvetica', 'B', 12)
        self.cell(0, 8, f"{title}: {len(items)}", new_x="LMARGIN", new_y="NEXT")
        self.set_font('courier', '', 10)
        for item in items:
            self.cell(0, 5, f" - {item.get('url')} ({item.get('status')})", new_x="LMARGIN", new_y="NEXT")
        self.ln()

    def _add_api_list_sub_section(self, data, key, title):
        items = data.get(key, [])
        if not items: return
        self.set_font('helvetica', 'B', 12)
        self.cell(0, 8, f"{title}: {len(items)}", new_x="LMARGIN", new_y="NEXT")
        self.set_font('courier', '', 8)
        for count, item in enumerate(items):
            if count >= 50:
                self.cell(0, 5, f" ... and {len(items)-50} more.", new_x="LMARGIN", new_y="NEXT")
                break
            self.cell(0, 4, f" {item}", new_x="LMARGIN", new_y="NEXT")
        self.ln()

    def add_form_discovery_section(self, result):
        self.chapter_title("Form Discovery")
        data = get_data(result)
        if not data:
            self.chapter_body("No form data available.")
            return
            
        forms = data.get("forms", [])
        if not forms:
            self.chapter_body("No forms found.")
            return
            
        self.set_font('helvetica', 'B', 12)
        self.cell(0, 8, f"Forms Found: {len(forms)}", new_x="LMARGIN", new_y="NEXT")
        self.ln(2)
        
        self.set_font('courier', '', 10)
        
        # Header
        self.cell(100, 7, "Action", 1)
        self.cell(30, 7, "Method", 1)
        self.cell(30, 7, "Inputs", 1)
        self.ln()
        
        for form in forms:
            action = form.get("action") or "(self)"
            method = form.get("method", "get")
            input_count = len(form.get("inputs", []))
            
            # Truncate action
            if len(action) > 40: action = action[:37] + "..."
            
            self.cell(100, 7, action, 1)
            self.cell(30, 7, method.upper(), 1)
            self.cell(30, 7, str(input_count), 1)
            self.ln()
            
        self.ln()

    def add_pqc_section(self, result):
        self.chapter_title("Post-Quantum Cryptography (PQC) Readiness")
        data = get_data(result)
        if not data:
            self.chapter_body("No PQC data available.")
            return

        pqc = data.get("pqc_readiness", {})
        status = pqc.get("status", "Unknown")
        score = pqc.get("score", 0)
        
        # Color score
        if score >= 90: self.set_text_color(0, 150, 0) # Green
        elif score >= 60: self.set_text_color(200, 150, 0) # Orange/Yellow
        else: self.set_text_color(200, 0, 0) # Red

        self.set_font('helvetica', 'B', 14)
        self.cell(0, 10, f"Status: {status} (Score: {score}/100)", new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.ln(2)

        # Flags
        flags = pqc.get("flags", [])
        if flags:
            self.set_font('helvetica', 'B', 12)
            self.cell(0, 8, "Findings:", new_x="LMARGIN", new_y="NEXT")
            self.set_font('courier', '', 10)
            for flag in flags:
                self.cell(0, 5, f" [!] {flag}", new_x="LMARGIN", new_y="NEXT")
            self.ln(2)

        # Recommendations
        recs = pqc.get("recommendations", [])
        if recs:
            self.set_font('helvetica', 'B', 12)
            self.cell(0, 8, "Migration Recommendations:", new_x="LMARGIN", new_y="NEXT")
            self.set_font('helvetica', '', 10)
            for rec in recs:
                self.multi_cell(0, 5, f" * {rec}")
            self.ln()

        # Brief Explanation
        self.set_font('helvetica', 'I', 9)
        self.multi_cell(0, 4, "Post-Quantum Cryptography (PQC) protects against future threats from powerful quantum computers. YADS evaluates readiness based on TLS 1.3 support and hybrid key exchange capabilities.")
        self.ln()

    def add_external_links_section(self, scope_count: int, external_links: List[Dict[str, Any]]):
        """Adds external links analysis section."""
        self.chapter_title("Overview")
        self.set_font('helvetica', '', 11)
        self.cell(0, 5, f"Analysis Scope: {scope_count} Targets", new_x="LMARGIN", new_y="NEXT")
        self.cell(0, 5, f"External Domains Found: {len(external_links)}", new_x="LMARGIN", new_y="NEXT")
        self.ln(5)
        
        self.chapter_title("External Domains List")
        self._add_external_links_table_header()
        self.set_font('courier', '', 9)
        for item in external_links:
            self._add_external_link_row(item)

    def _add_external_links_table_header(self):
        self.set_font('helvetica', 'B', 10)
        self.set_fill_color(240, 240, 240)
        self.cell(70, 8, "Domain", border=1, fill=True)
        self.cell(25, 8, "Type", border=1, fill=True)
        self.cell(80, 8, "Sources (All)", border=1, fill=True)
        self.cell(15, 8, "Count", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

    def _add_external_link_row(self, item):
        domain  = _s(item.get("domain", ""))
        types   = _s(", ".join(item.get("types", [])))
        count   = _s(str(item.get("count", 0)))
        sources = _s(", ".join(item.get("sources", [])))

        x_start, y_start = self.get_x(), self.get_y()
        self.multi_cell(70, 7, domain, border=1, new_x="RIGHT", new_y="TOP")
        h1 = self.get_y() - y_start

        self.set_y(y_start)
        self.multi_cell(25, 7, types, border=1, new_x="RIGHT", new_y="TOP")
        h2 = self.get_y() - y_start

        self.set_y(y_start)
        self.multi_cell(80, 7, sources, border=1, new_x="RIGHT", new_y="TOP")
        h3 = self.get_y() - y_start

        self.set_y(y_start)
        self.multi_cell(15, 7, count, border=1, new_x="RIGHT", new_y="TOP")
        h4 = self.get_y() - y_start

        self.set_xy(x_start, y_start + max(h1, h2, h3, h4))

    def add_infra_exec_summary(self, data: Dict[str, Any]):
        """Adds infrastructure executive summary sections."""
        self._add_infra_summary_grid(data)
        self._add_infra_dist_table(data, "cloud_providers", "Cloud Provider Distribution", "Provider")
        self._add_infra_dist_table(data, "countries", "Geographic Distribution (Top 10)", "Country", limit=10)
        self._add_infra_dist_table(data, "tech_stack", "Technology Stack (Top 15)", "Technology", limit=15)
        self._add_infra_risk_feed(data)

    def _add_infra_summary_grid(self, data):
        self.chapter_title("Executive Overview")
        self.set_font('courier', 'B', 12)
        v_stats = data.get("vuln_stats", {})
        self.cell(90, 8, f"Cloud Providers: {len(data.get('cloud_providers', {}))}", border=1)
        self.cell(90, 8, f"Countries: {len(data.get('countries', {}))}", border=1, new_x="LMARGIN", new_y="NEXT")
        self.cell(90, 8, f"Total Vulnerabilities: {sum(v_stats.values())}", border=1)
        self.cell(90, 8, f"Critical Risks: {v_stats.get('critical', 0)}", border=1, new_x="LMARGIN", new_y="NEXT")
        self.ln(5)

    def _add_infra_dist_table(self, data, key, title, label, limit=None):
        dist = data.get(key, {})
        if not dist: return
        self.chapter_title(title)
        self.set_font('helvetica', 'B', 10)
        self.set_fill_color(240, 240, 240)
        self.cell(100, 8, label, border=1, fill=True)
        self.cell(40, 8, "Target Count", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
        
        self.set_font('courier', '', 10)
        items = sorted(dist.items(), key=lambda x: x[1], reverse=True)
        if limit: items = items[:limit]
        for k, v in items:
            self.cell(100, 7, k, border=1)
            self.cell(40, 7, str(v), border=1, new_x="LMARGIN", new_y="NEXT")
        self.ln(5)

    def _add_infra_risk_feed(self, data):
        risks = data.get("risk_feed", [])
        if not risks: return
        self.chapter_title("Critical Risk Feed (Top Items)")
        self.set_font('helvetica', 'B', 10)
        self.set_fill_color(255, 230, 230)
        self.cell(25, 8, "Severity", border=1, fill=True)
        self.cell(25, 8, "Type", border=1, fill=True)
        self.cell(130, 8, "Issue / Description", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
        self.set_font('courier', '', 9)
        for item in risks:
            self._add_risk_row(item)

    def _add_risk_row(self, item):
        sev = item.get("severity", "Unknown")
        if sev.lower() == "critical": self.set_text_color(200, 0, 0)
        elif sev.lower() == "high": self.set_text_color(200, 100, 0)
        
        x_start, _ = self.get_x(), self.get_y()
        self.multi_cell(25, 7, sev, border=1, new_x="RIGHT", new_y="TOP")
        self.set_text_color(0, 0, 0)
        self.multi_cell(25, 7, item.get("type", ""), border=1, new_x="RIGHT", new_y="TOP")
        self.multi_cell(130, 7, f"{item.get('title')} - {item.get('desc')}", border=1, new_x="RIGHT", new_y="TOP")
        self.set_xy(x_start, self.get_y())

def generate_report(target_domain: str, scan_results: Dict[str, Any]) -> bytes:
    pdf = PDFReport(target_domain)
    # Infra, DNS, Web, Typosquat, API, Form, SSL
    scanners = {
        'infrastructure_scanner': pdf.add_infra_section,
        'dns_scanner': pdf.add_dns_section,
        'web_analyzer': pdf.add_web_section,
        'typosquat_scanner': pdf.add_typosquat_section,
        'api_discovery': pdf.add_api_discovery_section,
        'form_discovery': pdf.add_form_discovery_section,
        'ssl_scanner': pdf.add_pqc_section
    }
    for mod_name, func in scanners.items():
        res = next((r for r in scan_results if r.module_name == mod_name), None)
        if res: func(res)
    return pdf.output()

def generate_pqc_report(target_domain: str, ssl_result: Dict[str, Any]) -> bytes:
    pdf = PDFReport(f"PQC Post-Quantum Audit ({target_domain})")
    pdf.chapter_title("Executive Summary - Post-Quantum Preparedness")
    pdf.set_font('helvetica', '', 11)
    pdf.multi_cell(0, 6, "This specialized audit evaluates the cryptographic resilience of the target against quantum computing threats.")
    pdf.ln(5)
    pdf.add_pqc_section(ssl_result)
    
    data = get_data(ssl_result)
    if data and data.get("ciphers"):
        pdf.chapter_title("Detailed TLS/SSL Configuration")
        pdf.set_font('helvetica', 'B', 10)
        pdf.cell(70, 8, "Cipher Suite", 1); pdf.cell(30, 8, "Protocol", 1); pdf.cell(30, 8, "Security", 1); pdf.ln()
        pdf.set_font('courier', '', 9)
        for c in data["ciphers"]:
            name = (c.get("name", "")[:32] + "...") if len(c.get("name", "")) > 35 else c.get("name", "")
            pdf.cell(70, 7, name, 1); pdf.cell(30, 7, c.get("version", ""), 1); pdf.cell(30, 7, str(c.get("bits", "")), 1); pdf.ln()
    return pdf.output()

def generate_external_links_report(scope_count: int, external_links: List[Dict[str, Any]], tenant_name: str = "Unknown") -> bytes:
    pdf = PDFReport(f"External Links Analysis ({tenant_name})")
    pdf.add_external_links_section(scope_count, external_links)
    return pdf.output()

# ---------------------------------------------------------------------------
# Modern Infrastructure Analytics PDF
# ---------------------------------------------------------------------------

class InfrastructurePDF(FPDF):
    # Colour palette
    C_BG       = (11, 15, 25)    # near-black page header
    C_PANEL    = (30, 41, 59)    # slate-800
    C_ACCENT   = (99, 102, 241)  # indigo-500
    C_CYAN     = (6, 182, 212)
    C_CRITICAL = (220, 38, 38)
    C_HIGH     = (234, 88, 12)
    C_MEDIUM   = (217, 119, 6)
    C_LOW      = (37, 99, 235)
    C_OK       = (22, 163, 74)
    C_TEXT     = (15, 23, 42)
    C_MUTED    = (100, 116, 139)
    C_ROWALT   = (241, 245, 249)  # slate-100 alternating rows

    def __init__(self, tenant_name: str, data: Dict[str, Any], ai_analysis: Dict[str, Any] = None):
        super().__init__()
        self.tenant_name = tenant_name
        self.d = data
        self.ai = ai_analysis
        self._toc_entries: List[tuple] = []
        self.set_auto_page_break(auto=True, margin=20)

    def _reset_fpdf(self):
        FPDF.__init__(self)
        self._toc_entries = []
        self.set_auto_page_break(auto=True, margin=20)

    def _build_sections(self):
        if self.ai:
            self._section_ai_management_summary()
            self._section_ai_risk_assessment()
        self._section_exec_summary()
        self._section_vuln_overview()
        self._section_cloud_providers()
        self._section_cloud_details()
        self._section_service_distribution()
        self._section_status_codes()
        self._section_geo_distribution()
        self._section_tech_stack()
        self._section_tech_details()
        self._section_attack_surface()
        self._section_ssl_expiry()
        self._section_reputation()
        self._section_open_buckets()
        self._section_secrets()
        self._section_risk_feed()
        self._section_vuln_table()

    def build(self):
        # Pass 1 — dry run: collect section page numbers (content starts at page 1)
        self.add_page()
        self._build_sections()
        toc_snapshot = list(self._toc_entries)

        # Reset: cover (p1) + intro (p2) + ToC (p3) + content (p4+), shift by +3
        self._reset_fpdf()
        self._cover_page()          # page 1 = cover
        self._intro_page()          # page 2 = intro / executive KPIs
        self.add_page()             # page 3 = ToC
        self._render_toc([(name, pg + 3) for name, pg in toc_snapshot])
        self.add_page()             # page 4 = first section
        self._build_sections()

    # ---- helpers ----

    @staticmethod
    def _s(text) -> str:
        """Delegate to module-level sanitizer."""
        return _s(text)

    def _rgb(self, c):
        self.set_fill_color(*c)

    def _text_rgb(self, c):
        self.set_text_color(*c)

    def _draw_rgb(self, c):
        self.set_draw_color(*c)

    def footer(self):
        self.set_y(-13)
        self._text_rgb(self.C_MUTED)
        self.set_font('helvetica', '', 8)
        self.cell(0, 5, f'YADS Analytics Export  |  {self.tenant_name}  |  Page {self.page_no()}', align='C')
        self._text_rgb(self.C_TEXT)

    def _render_toc(self, entries: List[tuple]):
        """Render title header + table of contents on first page."""
        # Title band
        self._rgb(self.C_BG)
        self.rect(0, 0, 210, 28, 'F')
        self._text_rgb((255, 255, 255))
        self.set_font('helvetica', 'B', 20)
        self.set_xy(self.l_margin, 5)
        self.cell(100, 10, 'YADS')
        self._text_rgb(self.C_CYAN)
        self.set_font('helvetica', '', 9)
        self.set_xy(self.l_margin, 16)
        self.cell(100, 6, 'Analytics Intelligence Report')
        # Tenant + date right-aligned
        self._text_rgb((148, 163, 184))
        self.set_font('helvetica', '', 9)
        self.set_xy(0, 8)
        self.cell(200, 6, datetime.datetime.now().strftime('%B %d, %Y'), align='R')
        self.set_xy(0, 16)
        self.cell(200, 6, self.tenant_name, align='R')
        self.set_y(34)

        # TOC header
        self._rgb(self.C_PANEL)
        self.rect(self.l_margin, self.get_y(), self.epw, 9, 'F')
        self._text_rgb((255, 255, 255))
        self.set_font('helvetica', 'B', 10)
        self.set_x(self.l_margin + 3)
        self.cell(self.epw - 3, 9, 'TABLE OF CONTENTS', new_x='LMARGIN', new_y='NEXT')
        self.ln(4)

        self.set_font('helvetica', '', 10)
        for name, pg in entries:
            self._text_rgb(self.C_TEXT)
            # Accent dot left
            self._rgb(self.C_ACCENT)
            self.rect(self.l_margin, self.get_y() + 3, 3, 3, 'F')
            self.set_x(self.l_margin + 6)
            # Section name
            self.cell(140, 8, name)
            # Dots
            self._text_rgb(self.C_MUTED)
            self.set_font('helvetica', '', 9)
            dots_x = self.l_margin + 6 + 140
            self.set_x(dots_x)
            self.cell(self.epw - 146 - 12, 8, '.' * 30, align='C')
            # Page number
            self._text_rgb(self.C_ACCENT)
            self.set_font('helvetica', 'B', 10)
            self.cell(12, 8, str(pg), align='R', new_x='LMARGIN', new_y='NEXT')
            self.set_font('helvetica', '', 10)
        self._text_rgb(self.C_TEXT)
        self.ln(4)

    def _section_header(self, title: str):
        """Dark banner section title — also registers ToC entry and adds page break."""
        if self.get_y() > self.t_margin + 5:
            self.add_page()
        self._toc_entries.append((title, self.page_no()))
        self._rgb(self.C_PANEL)
        self.rect(self.l_margin, self.get_y(), self.epw, 9, 'F')
        self._text_rgb((255, 255, 255))
        self.set_font('helvetica', 'B', 10)
        self.set_x(self.l_margin + 3)
        self.cell(self.epw - 3, 9, title.upper(), new_x='LMARGIN', new_y='NEXT')
        self._text_rgb(self.C_TEXT)
        self.ln(2)

    def _section_intro(self, text: str):
        """Light italic description block shown beneath a section header."""
        self._rgb((241, 245, 249))
        self.rect(self.l_margin, self.get_y(), self.epw, 0.4, 'F')
        self.ln(1)
        self.set_font('helvetica', 'I', 8)
        self._text_rgb(self.C_MUTED)
        self.set_x(self.l_margin)
        self.multi_cell(self.epw, 4.5, self._s(text), align='L')
        self._text_rgb(self.C_TEXT)
        self.ln(3)

    def _kpi_box(self, x, y, w, h, label, value, color):
        """Colored KPI card."""
        self._rgb((248, 250, 252))
        self._draw_rgb((226, 232, 240))
        self.set_line_width(0.2)
        self.rect(x, y, w, h, 'FD')
        # accent bar on left
        self._rgb(color)
        self.rect(x, y, 2, h, 'F')
        # value
        self._text_rgb(color)
        self.set_font('helvetica', 'B', 18)
        self.set_xy(x + 5, y + 3)
        self.cell(w - 7, 10, str(value), align='L')
        # label
        self._text_rgb(self.C_MUTED)
        self.set_font('helvetica', '', 8)
        self.set_xy(x + 5, y + h - 7)
        self.cell(w - 7, 5, label.upper(), align='L')
        self._text_rgb(self.C_TEXT)

    def _horiz_bar(self, x, y, bar_w, bar_h, value, max_val, color, label, count_str):
        """Single horizontal bar with label and value."""
        # label
        self._text_rgb(self.C_TEXT)
        self.set_font('helvetica', '', 8)
        self.set_xy(x, y)
        self.cell(55, bar_h, label[:30], align='L')
        # bar background
        self._rgb((226, 232, 240))
        self.rect(x + 57, y + 1, bar_w, bar_h - 2, 'F')
        # filled portion
        filled = int(bar_w * value / max_val) if max_val else 0
        if filled > 0:
            self._rgb(color)
            self.rect(x + 57, y + 1, filled, bar_h - 2, 'F')
        # count
        self._text_rgb(self.C_MUTED)
        self.set_font('helvetica', 'B', 8)
        self.set_xy(x + 57 + bar_w + 2, y)
        self.cell(20, bar_h, count_str, align='L')
        self._text_rgb(self.C_TEXT)

    # ---- pages ----

    def _cover_page(self):
        import os
        self.add_page()
        now = datetime.datetime.now()

        # ── Full dark header band ──────────────────────────────────────────
        self._rgb(self.C_BG)
        self.rect(0, 0, 210, 95, 'F')

        # Accent stripe bottom of band
        self._rgb(self.C_ACCENT)
        self.rect(0, 92, 210, 3, 'F')

        # YADS logo image (top-left inside band)
        logo_path = '/app/yads/api/static/logo.png'
        if os.path.exists(logo_path):
            try:
                self.image(logo_path, x=12, y=12, h=22)
            except Exception:
                pass

        # "YADS" fallback text if logo missing or as subtitle
        self._text_rgb((255, 255, 255))
        self.set_font('helvetica', 'B', 11)
        self.set_xy(12, 38)
        self.cell(60, 6, 'YADS Security Intelligence', align='L')

        # Report type label — right side
        self._text_rgb(self.C_CYAN)
        self.set_font('helvetica', 'B', 10)
        self.set_xy(100, 20)
        self.cell(98, 6, 'INFRASTRUCTURE & SECURITY', align='R')
        self._text_rgb((148, 163, 184))
        self.set_font('helvetica', '', 9)
        self.set_xy(100, 28)
        self.cell(98, 5, 'Executive Report', align='R')

        # Date + classification — right side
        self.set_xy(100, 60)
        self._text_rgb((148, 163, 184))
        self.set_font('helvetica', '', 8)
        self.cell(98, 5, f'Generated: {now.strftime("%d. %B %Y, %H:%M UTC")}', align='R')
        self.set_xy(100, 67)
        self._rgb((220, 38, 38))
        self.rect(155, 66, 43, 7, 'F')
        self._text_rgb((255, 255, 255))
        self.set_font('helvetica', 'B', 8)
        self.set_xy(155, 67)
        self.cell(43, 5, 'CONFIDENTIAL', align='C')

        # ── Tenant / company block ────────────────────────────────────────
        self._text_rgb(self.C_TEXT)
        self.set_font('helvetica', 'B', 30)
        self.set_xy(12, 108)
        self.cell(186, 14, self._s(self.tenant_name), align='L')

        self._text_rgb(self.C_MUTED)
        self.set_font('helvetica', '', 12)
        self.set_xy(12, 125)
        self.cell(186, 7, 'Infrastructure & Security Intelligence Report', align='L')

        # Accent divider
        self._rgb(self.C_ACCENT)
        self.rect(12, 136, 100, 1.2, 'F')

        # ── Three metadata lines ──────────────────────────────────────────
        self._text_rgb(self.C_MUTED)
        self.set_font('helvetica', '', 9)
        meta = [
            'Report Period:   All Time',
            'Classification:  CONFIDENTIAL - Internal Use Only',
            'Prepared by:     YADS Security Intelligence Platform',
        ]
        for idx, line in enumerate(meta):
            self.set_xy(12, 142 + idx * 9)
            self.cell(186, 6, self._s(line), align='L')

        # ── Footer: prepared by ───────────────────────────────────────────
        self._rgb((241, 245, 249))
        self.rect(0, 244, 210, 14, 'F')
        self._text_rgb(self.C_MUTED)
        self.set_font('helvetica', 'I', 8)
        self.set_xy(12, 248)
        self.cell(90, 5, 'Prepared by YADS Security Intelligence Platform', align='L')
        self.set_xy(100, 248)
        self.cell(98, 5, f'Report Date: {now.strftime("%Y-%m-%d")}   |   Classification: CONFIDENTIAL', align='R')

    def _intro_page(self):
        """Page 2 — Executive KPI overview + document introduction."""
        self.add_page()
        now = datetime.datetime.now()
        d = self.d
        vs   = d.get('vuln_stats', {})
        total_vulns = sum(vs.values())
        sds  = d.get('service_distribution_stats', {})
        total_svc   = sum(sds.values()) or 1
        https_pct   = round(100 * (sds.get('HTTPS Only', 0) + sds.get('Both', 0)) / total_svc)
        rep_count   = len(d.get('reputation_issues', []))
        techs_count = len(d.get('tech_stack', {}))

        # ── Header band ───────────────────────────────────────────────────
        self._rgb(self.C_PANEL)
        self.rect(0, 0, 210, 20, 'F')
        self._text_rgb(self.C_CYAN)
        self.set_font('helvetica', 'B', 12)
        self.set_xy(self.l_margin, 6)
        self.cell(self.epw, 8, 'INFRASTRUCTURE & SECURITY EXECUTIVE SUMMARY', align='L')
        self._text_rgb((148, 163, 184))
        self.set_font('helvetica', '', 8)
        self.set_xy(self.l_margin, 14)
        self.cell(self.epw / 2, 5, self._s(self.tenant_name), align='L')
        self.set_xy(self.l_margin, 14)
        self.cell(self.epw, 5, now.strftime('%d %B %Y'), align='R')
        self.set_y(26)

        # ── KPI boxes — Row 1 (scope) ─────────────────────────────────────
        kgap, kh = 4, 28
        kw = (self.epw - 3 * kgap) / 4
        row1 = [
            ('Targets Scoped',  len(d.get('cloud_details', [])),      self.C_ACCENT),
            ('Cloud Providers', len(d.get('cloud_providers', {})),     self.C_CYAN),
            ('Countries',       len(d.get('countries', {})),           self.C_OK),
            ('Technologies',    techs_count,                           self.C_ACCENT),
        ]
        row2 = [
            ('Total Vulns',     total_vulns, self.C_CRITICAL if total_vulns else self.C_OK),
            ('Critical Vulns',  vs.get('critical', 0),                 self.C_CRITICAL),
            ('High Vulns',      vs.get('high', 0),                     self.C_HIGH),
            ('HTTPS Coverage',  f'{https_pct}%', self.C_OK if https_pct >= 80 else self.C_MEDIUM),
        ]
        ky1 = self.get_y()
        for i, (lbl, val, col) in enumerate(row1):
            self._kpi_box(self.l_margin + i * (kw + kgap), ky1, kw, kh, lbl, val, col)
        ky2 = ky1 + kh + kgap
        for i, (lbl, val, col) in enumerate(row2):
            self._kpi_box(self.l_margin + i * (kw + kgap), ky2, kw, kh, lbl, val, col)
        self.set_y(ky2 + kh + 10)

        # ── Accent divider ────────────────────────────────────────────────
        self._rgb(self.C_ACCENT)
        self.rect(self.l_margin, self.get_y(), self.epw, 1, 'F')
        self.ln(6)

        # ── About this report ─────────────────────────────────────────────
        self._text_rgb(self.C_PANEL)
        self.set_font('helvetica', 'B', 10)
        self.set_x(self.l_margin)
        self.cell(self.epw, 6, 'ABOUT THIS REPORT', new_x='LMARGIN', new_y='NEXT')
        self.ln(3)

        about_text = (
            'This report provides a comprehensive, automated security intelligence assessment of the '
            'monitored infrastructure within the YADS platform. It is generated from the aggregated '
            'results of all active scanner modules and reflects the security posture at the time of '
            'generation.'
        )
        self._text_rgb(self.C_TEXT)
        self.set_font('helvetica', '', 9)
        self.set_x(self.l_margin)
        self.multi_cell(self.epw, 5.5, self._s(about_text), align='L')
        self.ln(5)

        # ── Two-column: Target Audience | Report Scope ───────────────────
        col_w = (self.epw - 6) / 2

        # Left column header
        left_x = self.l_margin
        right_x = self.l_margin + col_w + 6
        col_y  = self.get_y()

        self._rgb(self.C_ROWALT)
        self.rect(left_x, col_y, col_w, 7, 'F')
        self.rect(right_x, col_y, col_w, 7, 'F')
        self._text_rgb(self.C_PANEL)
        self.set_font('helvetica', 'B', 9)
        self.set_xy(left_x + 3, col_y + 1)
        self.cell(col_w - 3, 6, 'TARGET AUDIENCE')
        self.set_xy(right_x + 3, col_y + 1)
        self.cell(col_w - 3, 6, 'REPORT SCOPE & CHAPTERS')

        audience_lines = [
            '* CISOs and Security Leadership',
            '* IT Risk and Compliance Officers',
            '* Infrastructure and Platform Teams',
            '* Auditors and external assessors',
            '* Executive Management (AI sections)',
        ]
        scope_lines = [
            '1. AI Management Summary (if enabled)',
            '2. Executive KPI Overview',
            '3. Vulnerability Landscape',
            '4. Cloud & Infrastructure Distribution',
            '5. SSL / TLS Certificate Status',
            '6. Reputation & Blacklist Intelligence',
            '7. Technology Stack & Attack Surface',
            '8. Secrets & Data Leak Detection',
            '9. Critical Risk Feed & Vuln Table',
        ]

        self.set_font('helvetica', '', 8.5)
        text_y = col_y + 10
        max_lines = max(len(audience_lines), len(scope_lines))
        for idx in range(max_lines):
            row_y = text_y + idx * 6.5
            if row_y + 8 > self.h - self.b_margin:
                break
            self._text_rgb(self.C_TEXT)
            if idx < len(audience_lines):
                self.set_xy(left_x + 3, row_y)
                self.cell(col_w - 3, 6, self._s(audience_lines[idx]), align='L')
            if idx < len(scope_lines):
                self.set_xy(right_x + 3, row_y)
                self.cell(col_w - 3, 6, self._s(scope_lines[idx]), align='L')

        self.set_y(text_y + max_lines * 6.5 + 6)

        # ── Disclaimer ────────────────────────────────────────────────────
        self._rgb((254, 243, 199))   # amber-50
        disclaimer_y = self.get_y()
        self.rect(self.l_margin, disclaimer_y, self.epw, 12, 'F')
        self._text_rgb((146, 64, 14))
        self.set_font('helvetica', 'I', 8)
        self.set_xy(self.l_margin + 3, disclaimer_y + 2)
        self.multi_cell(self.epw - 6, 4.5,
            'DISCLAIMER: This report is generated automatically by YADS and may not capture all '
            'security issues. Findings should be reviewed by a qualified security professional before '
            'remediation decisions are made. Classification: CONFIDENTIAL - do not distribute externally.',
            align='L')
        self._text_rgb(self.C_TEXT)

    def _section_exec_summary(self):
        d = self.d
        vs = d.get('vuln_stats', {})
        total_vulns = sum(vs.values())
        sds = d.get('service_distribution_stats', {})
        total_svc = sum(sds.values()) or 1
        https_pct = round(100 * (sds.get('HTTPS Only', 0) + sds.get('Both', 0)) / total_svc)

        self._section_header('Executive Summary')
        self._section_intro('Provides a concise overview of the entire monitored infrastructure. The KPI tiles show the most important metrics at a glance: number of scanned targets, cloud providers, countries, technologies in use, and detected vulnerabilities. Use this view for management presentations and status reports.')
        kh = 28
        kpis = [
            ('Targets', len(d.get('cloud_details', [])), self.C_ACCENT),
            ('Cloud Providers', len(d.get('cloud_providers', {})), self.C_CYAN),
            ('Countries', len(d.get('countries', {})), self.C_OK),
            ('Technologies', len(d.get('tech_stack', {})), self.C_ACCENT),
            ('Total Vulns', total_vulns, self.C_CRITICAL if total_vulns else self.C_OK),
        ]
        n = len(kpis)
        kgap = 4
        kw = (self.epw - (n - 1) * kgap) / n
        ky = self.get_y()
        for i, (lbl, val, col) in enumerate(kpis):
            kx = self.l_margin + i * (kw + kgap)
            self._kpi_box(kx, ky, kw, kh, lbl, val, col)
        self.set_y(ky + kh + 6)

        # HTTPS coverage bar
        self.set_font('helvetica', '', 9)
        self._text_rgb(self.C_MUTED)
        self.cell(self.epw, 5, f'HTTPS Coverage: {https_pct}%  ({sds.get("HTTPS Only",0) + sds.get("Both",0)} of {total_svc} targets with port data)', new_x='LMARGIN', new_y='NEXT')
        bar_full = self.epw
        self._rgb((226, 232, 240))
        self.rect(self.l_margin, self.get_y(), bar_full, 5, 'F')
        self._rgb(self.C_OK if https_pct >= 80 else self.C_HIGH if https_pct >= 50 else self.C_CRITICAL)
        self.rect(self.l_margin, self.get_y(), bar_full * https_pct / 100, 5, 'F')
        self.ln(10)

    def _section_vuln_overview(self):
        vs = self.d.get('vuln_stats', {})
        total = sum(vs.values()) or 1
        self._section_header('Vulnerability Overview')
        self._section_intro('Lists all identified security vulnerabilities classified by CVSS severity (Critical, High, Medium, Low). Results are sourced from automated Nuclei scans. Critical and high findings should be addressed with priority. The detail table at the end of the report lists each vulnerability with its target, description, and CVE reference.')

        sev_defs = [
            ('Critical', vs.get('critical', 0), self.C_CRITICAL),
            ('High',     vs.get('high', 0),     self.C_HIGH),
            ('Medium',   vs.get('medium', 0),   self.C_MEDIUM),
            ('Low',      vs.get('low', 0),       self.C_LOW),
        ]
        bw, bh, gap = 38, 24, 5
        ky = self.get_y()
        for i, (lbl, val, col) in enumerate(sev_defs):
            kx = self.l_margin + i * (bw + gap)
            self._kpi_box(kx, ky, bw, bh, lbl, val, col)
            # percentage sub-bar
            pct = val / total
            self._rgb((226, 232, 240))
            self.rect(kx, ky + bh, bw, 3, 'F')
            if pct:
                self._rgb(col)
                self.rect(kx, ky + bh, bw * pct, 3, 'F')
        self.set_y(ky + bh + 8)
        self.ln(2)

    def _horiz_bar_chart(self, items, color, max_bars=15):
        """items: list of (label, count). Sorted descending."""
        if not items:
            self._text_rgb(self.C_MUTED)
            self.set_font('helvetica', 'I', 9)
            self.cell(self.epw, 6, 'No data available.', new_x='LMARGIN', new_y='NEXT')
            self._text_rgb(self.C_TEXT)
            self.ln(2)
            return
        items = sorted(items, key=lambda x: x[1], reverse=True)[:max_bars]
        max_val = items[0][1] if items else 1
        bar_area = self.epw - 57 - 25  # label=55 + gap=2, count=20
        bar_h = 7
        for label, count in items:
            if self.get_y() + bar_h + 4 > self.h - self.b_margin:
                self.add_page()
            self._horiz_bar(self.l_margin, self.get_y(), bar_area, bar_h, count, max_val, color, label, str(count))
            self.ln(bar_h + 1)
        self.ln(4)

    def _section_cloud_providers(self):
        self._section_header('Cloud Infrastructure Distribution')
        self._section_intro('Shows the distribution of infrastructure across cloud providers (AWS, GCP, Azure, etc.) based on the resolved IP addresses of scanned targets. Provides an overview of provider dependencies and diversification. A high concentration with a single provider may represent a concentration risk.')
        cp = self.d.get('cloud_providers', {})
        self._horiz_bar_chart(list(cp.items()), self.C_ACCENT)

    def _section_service_distribution(self):
        self._section_header('HTTP/HTTPS Service Distribution')
        self._section_intro('Classifies all targets by their protocol behaviour: HTTPS Only (secure), HTTP Only (insecure), both active, or unreachable. Targets without HTTPS redirection are vulnerable to man-in-the-middle attacks. The "HTTPS Only" share is a direct indicator of transport security maturity.')
        sds = self.d.get('service_distribution_stats', {})
        colors = {
            'HTTPS Only': self.C_OK,
            'Both': self.C_CYAN,
            'HTTP Only': self.C_HIGH,
            'None': self.C_MUTED,
        }
        if not any(sds.values()):
            self._text_rgb(self.C_MUTED)
            self.set_font('helvetica', 'I', 9)
            self.cell(self.epw, 6, 'No port scan data available.', new_x='LMARGIN', new_y='NEXT')
            self._text_rgb(self.C_TEXT)
            self.ln(6)
            return
        max_val = max(sds.values()) or 1
        bar_area = self.epw - 57 - 25
        bar_h = 8
        order = ['HTTPS Only', 'Both', 'HTTP Only', 'None']
        for key in order:
            val = sds.get(key, 0)
            if self.get_y() + bar_h + 4 > self.h - self.b_margin:
                self.add_page()
            self._horiz_bar(self.l_margin, self.get_y(), bar_area, bar_h, val, max_val,
                            colors.get(key, self.C_ACCENT), key, str(val))
            self.ln(bar_h + 2)
        self.ln(4)

    def _section_geo_distribution(self):
        self._section_header('Geographic Distribution (Top 15)')
        self._section_intro('Shows which countries host the infrastructure based on IP geolocation. Helps identify unexpected hosting locations and potential regulatory concerns (e.g. GDPR data residency). Servers in high-risk jurisdictions may warrant additional scrutiny.')
        countries = self.d.get('countries', {})
        self._horiz_bar_chart(list(countries.items()), self.C_CYAN, max_bars=15)

    def _section_tech_stack(self):
        self._section_header('Technology Stack (Top 15)')
        self._section_intro('Identifies the most widely used web technologies (frameworks, servers, CMS, analytics) across all scanned targets. Outdated or end-of-life software versions represent significant vulnerability risk. Use this view to prioritize patching and assess software supply chain exposure.')
        tech = self.d.get('tech_stack', {})
        self._horiz_bar_chart(list(tech.items()), (139, 92, 246), max_bars=15)

    def _section_attack_surface(self):
        atk = self.d.get('attack_surface_stats', [])
        if not atk:
            return
        self._section_header('Attack Surface - Subdomain Exposure (Top 10)')
        self._section_intro('Ranks targets by the number of discovered subdomains. A large subdomain count increases the attack surface and the likelihood of forgotten or unpatched services. Each subdomain is a potential entry point for attackers if not actively maintained.')
        max_val = max(a['count'] for a in atk) if atk else 1
        bar_area = self.epw - 57 - 25
        bar_h = 7
        for a in atk[:10]:
            if self.get_y() + bar_h + 4 > self.h - self.b_margin:
                self.add_page()
            self._horiz_bar(self.l_margin, self.get_y(), bar_area, bar_h,
                            a['count'], max_val, self.C_HIGH, a['target'], str(a['count']))
            self.ln(bar_h + 1)
        self.ln(4)

    def _sev_color(self, sev: str):
        s = sev.lower()
        if s == 'critical': return self.C_CRITICAL
        if s == 'high':     return self.C_HIGH
        if s == 'medium':   return self.C_MEDIUM
        return self.C_LOW

    def _section_risk_feed(self):
        risks = self.d.get('risk_feed', [])
        self._section_header(f'Critical Risk Feed ({len(risks)} items)')
        self._section_intro('Aggregated feed of high and critical severity findings across all modules (vulnerability scanner, web analyzer, DNS, SSL). Items are sorted by severity. Each entry includes the affected target and a description — use this as an action list for the security team.')
        if not risks:
            self._text_rgb(self.C_MUTED)
            self.set_font('helvetica', 'I', 9)
            self.cell(self.epw, 6, 'No high/critical risks detected.', new_x='LMARGIN', new_y='NEXT')
            self._text_rgb(self.C_TEXT)
            self.ln(6)
            return

        # Header row
        self._rgb(self.C_PANEL)
        self.set_line_width(0)
        self.rect(self.l_margin, self.get_y(), self.epw, 8, 'F')
        self._text_rgb((255, 255, 255))
        self.set_font('helvetica', 'B', 8)
        self.set_x(self.l_margin)
        self.cell(22, 8, 'SEVERITY')
        self.cell(22, 8, 'TYPE')
        self.cell(50, 8, 'TITLE')
        self.cell(0, 8, 'DESCRIPTION', new_x='LMARGIN', new_y='NEXT')
        self._text_rgb(self.C_TEXT)

        for i, item in enumerate(risks):
            row_h = 7
            if self.get_y() + row_h + 2 > self.h - self.b_margin:
                self.add_page()
            y0 = self.get_y()
            # alternating bg
            if i % 2 == 0:
                self._rgb(self.C_ROWALT)
                self.rect(self.l_margin, y0, self.epw, row_h, 'F')
            sev = item.get('severity', 'Low')
            col = self._sev_color(sev)
            # severity pill
            self._rgb(col)
            self.rect(self.l_margin, y0 + 1.5, 20, row_h - 3, 'F')
            self._text_rgb((255, 255, 255))
            self.set_font('helvetica', 'B', 7)
            self.set_xy(self.l_margin, y0)
            self.cell(20, row_h, sev[:8].upper(), align='C')
            # other cells
            self._text_rgb(self.C_TEXT)
            self.set_font('helvetica', '', 8)
            self.set_xy(self.l_margin + 22, y0)
            self.cell(22, row_h, str(item.get('type', ''))[:14])
            self.set_xy(self.l_margin + 44, y0)
            self.cell(50, row_h, str(item.get('title', ''))[:30])
            self.set_xy(self.l_margin + 94, y0)
            desc = str(item.get('desc', '') or '')
            self.cell(0, row_h, desc[:70] + ('...' if len(desc) > 70 else ''), new_x='LMARGIN', new_y='NEXT')
        self.ln(6)

    def _section_vuln_table(self):
        vulns = self.d.get('vulnerabilities', [])
        if not vulns:
            return
        self._section_header(f'Vulnerability Detail ({len(vulns)} total)')
        self._section_intro('Full table of all detected vulnerabilities (capped at 100 entries) sorted by severity. Each row contains the CVE identifier, affected target, product/component, and a brief description. Cross-reference with the CVE database for patch availability and CVSS base scores.')

        # Header
        self._rgb(self.C_PANEL)
        self.rect(self.l_margin, self.get_y(), self.epw, 8, 'F')
        self._text_rgb((255, 255, 255))
        self.set_font('helvetica', 'B', 8)
        self.set_x(self.l_margin)
        self.cell(20, 8, 'SEVERITY')
        self.cell(28, 8, 'CVE ID')
        self.cell(45, 8, 'TARGET')
        self.cell(25, 8, 'PRODUCT')
        self.cell(0, 8, 'DESCRIPTION', new_x='LMARGIN', new_y='NEXT')
        self._text_rgb(self.C_TEXT)

        # Sort by severity
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        vulns_sorted = sorted(vulns, key=lambda v: sev_order.get(v.get('severity', 'LOW'), 3))

        for i, v in enumerate(vulns_sorted[:100]):
            row_h = 7
            if self.get_y() + row_h + 2 > self.h - self.b_margin:
                self.add_page()
            y0 = self.get_y()
            if i % 2 == 0:
                self._rgb(self.C_ROWALT)
                self.rect(self.l_margin, y0, self.epw, row_h, 'F')
            sev = v.get('severity', 'Low')
            col = self._sev_color(sev)
            self._rgb(col)
            self.rect(self.l_margin, y0 + 1.5, 18, row_h - 3, 'F')
            self._text_rgb((255, 255, 255))
            self.set_font('helvetica', 'B', 6)
            self.set_xy(self.l_margin, y0)
            self.cell(18, row_h, sev[:8].upper(), align='C')
            self._text_rgb(self.C_TEXT)
            self.set_font('helvetica', '', 8)
            self.set_xy(self.l_margin + 20, y0)
            self.cell(28, row_h, str(v.get('id', ''))[:18])
            self.set_xy(self.l_margin + 48, y0)
            self.cell(45, row_h, str(v.get('target', ''))[:25])
            self.set_xy(self.l_margin + 93, y0)
            self.cell(25, row_h, str(v.get('product', ''))[:15])
            self.set_xy(self.l_margin + 118, y0)
            desc = str(v.get('description', '') or '')
            self.cell(0, row_h, desc[:55] + ('...' if len(desc) > 55 else ''), new_x='LMARGIN', new_y='NEXT')

        if len(vulns) > 100:
            self._text_rgb(self.C_MUTED)
            self.set_font('helvetica', 'I', 8)
            self.cell(0, 6, f'... and {len(vulns) - 100} more vulnerabilities not shown.', new_x='LMARGIN', new_y='NEXT')
        self.ln(4)


    def _rating_color(self, rating: str):
        r = (rating or "").upper()
        if r == "CRITICAL": return self.C_CRITICAL
        if r == "HIGH":     return self.C_HIGH
        if r == "MEDIUM":   return self.C_MEDIUM
        return self.C_OK

    def _section_ai_management_summary(self):
        ai = self.ai
        rating = (ai.get("risk_rating") or "UNKNOWN").upper()
        color  = self._rating_color(rating)

        # Register & page break
        self._toc_entries.append(("Management Summary (AI)", self.page_no() if self.get_y() <= self.t_margin + 5 else self.page_no() + 1))
        if self.get_y() > self.t_margin + 5:
            self.add_page()

        # Intro
        self._section_intro('AI-generated executive summary based on aggregated scan data from all modules. The risk rating and score reflect the overall security posture of the monitored infrastructure. This summary is intended for C-level audiences and non-technical stakeholders. Always validate findings with your security team before acting.')

        # Banner
        self._rgb(self.C_BG)
        self.rect(self.l_margin, self.get_y(), self.epw, 10, 'F')
        self._text_rgb((255, 255, 255))
        self.set_font('helvetica', 'B', 10)
        self.set_x(self.l_margin + 3)
        self.cell(self.epw - 3, 10, 'MANAGEMENT SUMMARY  |  AI-GENERATED', new_x='LMARGIN', new_y='NEXT')
        self.ln(5)

        # Risk rating badge (large)
        badge_w, badge_h = 55, 18
        bx = self.l_margin
        by = self.get_y()
        self._rgb(color)
        self.rect(bx, by, badge_w, badge_h, 'F')
        self._text_rgb((255, 255, 255))
        self.set_font('helvetica', 'B', 13)
        self.set_xy(bx, by + 1)
        self.cell(badge_w, badge_h - 2, f'RISK: {rating}', align='C')

        # Score bar next to badge
        score = int(ai.get("risk_score") or 0)
        bar_x = bx + badge_w + 6
        bar_w = self.epw - badge_w - 6
        self._text_rgb(self.C_MUTED)
        self.set_font('helvetica', '', 8)
        self.set_xy(bar_x, by)
        self.cell(bar_w, 6, f'Risk Score: {score} / 100')
        self._rgb((226, 232, 240))
        self.rect(bar_x, by + 6, bar_w, 6, 'F')
        self._rgb(color)
        self.rect(bar_x, by + 6, bar_w * score / 100, 6, 'F')
        self.set_y(by + badge_h + 6)

        # Executive summary text
        summary = self._s(ai.get("executive_summary") or "")
        self._text_rgb(self.C_TEXT)
        self.set_font('helvetica', '', 10)
        self.multi_cell(self.epw, 6, summary)
        self.ln(4)

        # AI model disclaimer
        self._text_rgb(self.C_MUTED)
        self.set_font('helvetica', 'I', 7)
        self.cell(self.epw, 5, 'This summary was generated by an AI language model and should be reviewed by a qualified security professional.',
                  new_x='LMARGIN', new_y='NEXT')
        self.ln(4)

    def _section_ai_risk_assessment(self):
        ai = self.ai
        findings     = ai.get("key_findings", [])
        recs         = ai.get("recommendations", [])
        if not findings and not recs:
            return

        self._toc_entries.append(("AI Risk Assessment", self.page_no() if self.get_y() <= self.t_margin + 5 else self.page_no() + 1))
        if self.get_y() > self.t_margin + 5:
            self.add_page()

        # Intro
        self._section_intro('Detailed AI risk assessment with the most impactful security findings and prioritised remediation recommendations. Key findings highlight the issues most likely to be exploited or cause the greatest business impact. Recommendations are ordered by urgency and specificity.')

        # Banner
        self._rgb(self.C_PANEL)
        self.rect(self.l_margin, self.get_y(), self.epw, 9, 'F')
        self._text_rgb((255, 255, 255))
        self.set_font('helvetica', 'B', 10)
        self.set_x(self.l_margin + 3)
        self.cell(self.epw - 3, 9, 'AI RISK ASSESSMENT  |  KEY FINDINGS & RECOMMENDATIONS', new_x='LMARGIN', new_y='NEXT')
        self.ln(5)

        half = (self.epw - 6) / 2

        # --- Key Findings (left column) ---
        col_x = self.l_margin
        col_y = self.get_y()
        self._rgb(self.C_CRITICAL)
        self.rect(col_x, col_y, half, 7, 'F')
        self._text_rgb((255, 255, 255))
        self.set_font('helvetica', 'B', 9)
        self.set_xy(col_x + 3, col_y)
        self.cell(half - 3, 7, 'KEY FINDINGS')
        self.set_y(col_y + 9)
        self._text_rgb(self.C_TEXT)
        self.set_font('helvetica', '', 9)
        for f in findings:
            self.set_x(col_x)
            self._rgb(self.C_CRITICAL)
            self.rect(col_x, self.get_y() + 2.5, 2, 2.5, 'F')
            self.set_x(col_x + 5)
            self.multi_cell(half - 5, 5, self._s(f))
            self.ln(1)

        # --- Recommendations (right column) ---
        col2_x = self.l_margin + half + 6
        self.set_xy(col2_x, col_y)
        self._rgb(self.C_OK)
        self.rect(col2_x, col_y, half, 7, 'F')
        self._text_rgb((255, 255, 255))
        self.set_font('helvetica', 'B', 9)
        self.set_xy(col2_x + 3, col_y)
        self.cell(half - 3, 7, 'RECOMMENDATIONS')
        self.set_xy(col2_x, col_y + 9)
        self._text_rgb(self.C_TEXT)
        self.set_font('helvetica', '', 9)
        for i, r in enumerate(recs, 1):
            self.set_x(col2_x)
            self._rgb(self.C_OK)
            self.rect(col2_x, self.get_y() + 2.5, 2, 2.5, 'F')
            self.set_x(col2_x + 5)
            self.multi_cell(half - 5, 5, self._s(f"{i}. {r}"))
            self.ln(1)

        self._text_rgb(self.C_TEXT)
        self.ln(4)

    def _simple_table(self, headers: List[str], rows: List[List[str]], col_widths: List[float]):
        """Generic bordered table with alternating rows."""
        # header
        self._rgb(self.C_PANEL)
        self.rect(self.l_margin, self.get_y(), self.epw, 8, 'F')
        self._text_rgb((255, 255, 255))
        self.set_font('helvetica', 'B', 8)
        self.set_x(self.l_margin)
        for h, w in zip(headers, col_widths):
            self.cell(w, 8, h)
        self.ln(8)
        self._text_rgb(self.C_TEXT)
        self.set_font('helvetica', '', 8)
        for i, row in enumerate(rows):
            row_h = 6
            if self.get_y() + row_h + 2 > self.h - self.b_margin:
                self.add_page()
            y0 = self.get_y()
            if i % 2 == 0:
                self._rgb(self.C_ROWALT)
                self.rect(self.l_margin, y0, self.epw, row_h, 'F')
            self.set_x(self.l_margin)
            for val, w in zip(row, col_widths):
                self.cell(w, row_h, str(val)[:int(w * 1.5)])
            self.ln(row_h)
        self.ln(4)

    def _section_cloud_details(self):
        details = self.d.get('cloud_details', [])
        if not details:
            return
        self._section_header(f'Cloud Details ({len(details)} targets)')
        self._section_intro('Per-target breakdown showing which cloud provider hosts each asset and its resolved IP address. Useful for verifying hosting decisions, identifying unexpected providers, and confirming IP ownership before engaging in penetration tests.')
        col_w = [self.epw * 0.40, self.epw * 0.30, self.epw * 0.30]
        rows = [[d.get('target', ''), d.get('provider', ''), d.get('ip', '')] for d in details[:200]]
        self._simple_table(['TARGET', 'PROVIDER', 'IP ADDRESS'], rows, col_w)

    def _section_status_codes(self):
        sc = self.d.get('status_codes', {})
        if not sc:
            return
        self._section_header('HTTP Status Code Distribution')
        self._section_intro('Breakdown of HTTP response codes returned by all scanned targets. 2xx = healthy, 3xx = redirects, 4xx = client errors (may indicate removed pages), 5xx = server errors (may indicate unstable services). A high proportion of 5xx or direct HTTP 200 without HTTPS redirect warrants investigation.')
        items = sorted(sc.items(), key=lambda x: x[1], reverse=True)
        bar_area = self.epw - 57 - 25
        bar_h = 7
        max_val = items[0][1] if items else 1
        sc_colors = {'200': self.C_OK, '301': self.C_CYAN, '302': self.C_CYAN,
                     '400': self.C_MEDIUM, '403': self.C_HIGH, '404': self.C_MEDIUM,
                     '500': self.C_CRITICAL, '503': self.C_HIGH}
        for code, count in items:
            if self.get_y() + bar_h + 4 > self.h - self.b_margin:
                self.add_page()
            color = sc_colors.get(str(code), self.C_ACCENT)
            self._horiz_bar(self.l_margin, self.get_y(), bar_area, bar_h, count, max_val,
                            color, f'HTTP {code}', str(count))
            self.ln(bar_h + 1)
        self.ln(4)

    def _section_tech_details(self):
        details = self.d.get('tech_details', [])
        if not details:
            return
        self._section_header(f'Technology Details ({len(details)} targets)')
        self._section_intro('Detailed per-target view of detected web technologies, server headers, and software stacks. Use this table to identify outdated CMS versions, unpatched frameworks, or mismatched server software that could be exploited.')
        col_w = [self.epw * 0.35, self.epw * 0.45, self.epw * 0.20]
        rows = []
        for d in details[:200]:
            techs = ', '.join(d.get('technologies', []))[:60]
            server = str(d.get('server_header') or '')[:20]
            rows.append([d.get('target', ''), techs, server])
        self._simple_table(['TARGET', 'TECHNOLOGIES', 'SERVER'], rows, col_w)

    def _ssl_status_color(self, status: str):
        s = status.lower()
        if s == 'expired':   return self.C_CRITICAL
        if s == 'critical':  return self.C_CRITICAL
        if s == 'warning':   return self.C_HIGH
        return self.C_OK

    def _section_ssl_expiry(self):
        ssl = self.d.get('ssl_timeline', [])
        self._section_header(f'SSL Certificate Expiry Timeline ({len(ssl)} targets)')
        self._section_intro('Lists SSL/TLS certificate expiry dates for all scanned targets. Expired certificates cause browser security warnings and break encrypted connections. Certificates expiring within 30 days (WARNING) or already expired (CRITICAL) require immediate renewal to avoid service disruption.')
        if not ssl:
            self._text_rgb(self.C_MUTED)
            self.set_font('helvetica', 'I', 9)
            self.cell(self.epw, 6, 'No SSL data available.', new_x='LMARGIN', new_y='NEXT')
            self._text_rgb(self.C_TEXT)
            self.ln(4)
            return
        col_w = [self.epw * 0.40, self.epw * 0.22, self.epw * 0.18, self.epw * 0.20]
        # header
        self._rgb(self.C_PANEL)
        self.rect(self.l_margin, self.get_y(), self.epw, 8, 'F')
        self._text_rgb((255, 255, 255))
        self.set_font('helvetica', 'B', 8)
        self.set_x(self.l_margin)
        for h, w in zip(['TARGET', 'EXPIRY DATE', 'DAYS LEFT', 'STATUS'], col_w):
            self.cell(w, 8, h)
        self.ln(8)
        self._text_rgb(self.C_TEXT)
        for i, item in enumerate(ssl):
            row_h = 6
            if self.get_y() + row_h + 2 > self.h - self.b_margin:
                self.add_page()
            y0 = self.get_y()
            if i % 2 == 0:
                self._rgb(self.C_ROWALT)
                self.rect(self.l_margin, y0, self.epw, row_h, 'F')
            status = item.get('status', 'ok')
            col = self._ssl_status_color(status)
            self.set_font('helvetica', '', 8)
            self.set_x(self.l_margin)
            self.cell(col_w[0], row_h, str(item.get('target', ''))[:35])
            self.cell(col_w[1], row_h, str(item.get('expiry_date', '')))
            days = item.get('days_left', 0)
            self._text_rgb(col)
            self.cell(col_w[2], row_h, str(days))
            self.set_font('helvetica', 'B', 8)
            self.cell(col_w[3], row_h, status.upper())
            self._text_rgb(self.C_TEXT)
            self.set_font('helvetica', '', 8)
            self.ln(row_h)
        self.ln(4)

    def _section_reputation(self):
        rep = self.d.get('reputation_issues', [])
        if not rep:
            return
        self._section_header(f'Reputation / Blacklist Issues ({len(rep)} targets)')
        self._section_intro('Targets whose IP addresses appear on threat intelligence blacklists (Spamhaus, SORBS, etc.). Blacklisted IPs may indicate compromised servers, spam activity, or botnet membership. Immediate investigation and remediation is recommended — being listed can impact email deliverability and brand reputation.')
        col_w = [self.epw * 0.35, self.epw * 0.20, self.epw * 0.45]
        rows = []
        for item in rep:
            def _fmt(x):
                if isinstance(x, dict):
                    return x.get('message') or x.get('source') or x.get('link', '')
                return str(x)
            issues = _s(', '.join(_fmt(x) for x in item.get('issues', [])))[:80]
            rows.append([_s(item.get('target', '')), _s(item.get('ip', '')), issues])
        self._simple_table(['TARGET', 'IP', 'BLACKLIST FLAGS'], rows, col_w)

    def _section_open_buckets(self):
        buckets = self.d.get('open_buckets', [])
        if not buckets:
            return
        self._section_header(f'Open Cloud Bucket Alerts ({len(buckets)} found)')
        self._section_intro('Publicly accessible cloud storage buckets (S3, GCS, Azure Blob) detected during infrastructure scans. Open buckets can expose sensitive files, internal documents, or credentials to anyone on the internet. Each finding should be investigated and access permissions restricted immediately.')
        col_w = [self.epw * 0.30, self.epw * 0.55, self.epw * 0.15]
        rows = [[b.get('target', ''), b.get('url', ''), str(b.get('code', ''))] for b in buckets]
        self._simple_table(['TARGET', 'BUCKET URL', 'HTTP CODE'], rows, col_w)

    def _section_secrets(self):
        leaks = self.d.get('secrets_leaks', [])
        if not leaks:
            return
        self._section_header(f'Secrets & Data Leaks ({len(leaks)} targets affected)')
        self._section_intro('Credentials, API keys, tokens, and other sensitive strings detected in publicly accessible web content (HTML, JS, config files). Exposed secrets can lead to full account compromise or data breaches. Each entry must be treated as compromised and rotated immediately regardless of whether active exploitation is confirmed.')
        # header
        self._rgb(self.C_PANEL)
        self.rect(self.l_margin, self.get_y(), self.epw, 8, 'F')
        self._text_rgb((255, 255, 255))
        self.set_font('helvetica', 'B', 8)
        self.set_x(self.l_margin)
        cw = [self.epw * 0.35, self.epw * 0.10, self.epw * 0.25, self.epw * 0.30]
        for h, w in zip(['TARGET', 'COUNT', 'SECRET TYPE', 'SNIPPET'], cw):
            self.cell(w, 8, h)
        self.ln(8)
        self._text_rgb(self.C_TEXT)
        row_i = 0
        for item in leaks:
            secrets = item.get('secrets', [])
            for s in (secrets[:10] if secrets else [{}]):
                row_h = 6
                if self.get_y() + row_h + 2 > self.h - self.b_margin:
                    self.add_page()
                y0 = self.get_y()
                if row_i % 2 == 0:
                    self._rgb(self.C_ROWALT)
                    self.rect(self.l_margin, y0, self.epw, row_h, 'F')
                self._rgb(self.C_CRITICAL)
                self.rect(self.l_margin, y0 + 1, 2, row_h - 2, 'F')
                self.set_font('helvetica', '', 8)
                self.set_x(self.l_margin)
                self.cell(cw[0], row_h, str(item.get('target', ''))[:30])
                self.cell(cw[1], row_h, str(item.get('count', '')))
                self.cell(cw[2], row_h, str(s.get('type', '') or '')[:22])
                snippet = str(s.get('snippet', '') or s.get('value', '') or '')
                self.cell(cw[3], row_h, snippet[:30])
                self.ln(row_h)
                row_i += 1
        self.ln(4)


def generate_infrastructure_report(data: Dict[str, Any], tenant_name: str = "Global",
                                    ai_analysis: Dict[str, Any] = None) -> bytes:
    pdf = InfrastructurePDF(tenant_name, data, ai_analysis=ai_analysis)
    pdf.build()
    return pdf.output()
