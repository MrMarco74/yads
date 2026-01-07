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
                self.cell(0, 5, f"{k}:", new_x="LMARGIN", new_y="NEXT")
                if isinstance(v, dict):
                    self.add_section_dict(v, indent + 5)
                else: # list
                    for item in v:
                        self.set_x(self.l_margin + indent + 5)
                        self.cell(0, 5, f"- {item}", new_x="LMARGIN", new_y="NEXT")
            else:
                text = f"{k}: {v}"
                # Handle long text
                self.multi_cell(0, 5, text)

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

def generate_report(target_domain: str, scan_results: Dict[str, Any]) -> bytes:
    pdf = PDFReport(target_domain)
    
    # Iterate and add sections
    # Order: Infra, DNS, Web, Typosquat
    
    # Infrastructure
    infra_scanner = next((r for r in scan_results if r.module_name == 'infrastructure_scanner'), None)
    if infra_scanner:
        # Since we are passing ORM objects usually, we need to be careful.
        # But report_generator should receive dicts or similar.
        # Let's assume we pass the .model_dump() or similar dict representation.
        pdf.add_infra_section(infra_scanner)
    
    # DNS
    dns_scanner = next((r for r in scan_results if r.module_name == 'dns_scanner'), None)
    if dns_scanner:
        pdf.add_dns_section(dns_scanner)

    # Web
    web_scanner = next((r for r in scan_results if r.module_name == 'web_analyzer'), None)
    if web_scanner:
        pdf.add_web_section(web_scanner)
        
    # Typosquat
    typo_scanner = next((r for r in scan_results if r.module_name == 'typosquat_scanner'), None)
    if typo_scanner:
        pdf.add_typosquat_section(typo_scanner)

    return pdf.output()
