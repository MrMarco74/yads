from fpdf import FPDF
from typing import Dict, Any, List
import datetime
import io

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
        domain, types, count = item.get("domain", ""), ", ".join(item.get("types", [])), str(item.get("count", 0))
        sources = ", ".join(item.get("sources", []))
        
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

def generate_infrastructure_report(data: Dict[str, Any], tenant_name: str = "Global") -> bytes:
    pdf = PDFReport(f"Infrastructure Executive Summary ({tenant_name})")
    pdf.add_infra_exec_summary(data)
    return pdf.output()
