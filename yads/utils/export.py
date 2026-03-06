
import io
import json
import pandas as pd
from fpdf import FPDF
from datetime import datetime
from fastapi import Response
from typing import List, Dict, Any

def generate_excel(data: List[Dict[str, Any]], filename_prefix: str) -> Response:
    """
    Generates an Excel file from a list of dictionaries.
    """
    if not data:
        df = pd.DataFrame()
    else:
        df = pd.DataFrame(data)
    
    output = io.BytesIO()
    # verify openpyxl is installed/used by pandas default or specify engine='openpyxl'
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Sheet1')
        
    output.seek(0)
    
    filename = f"{filename_prefix}_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.xlsx"
    
    return Response(
        content=output.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

def generate_api_excel(data: Dict[str, Any], filename_prefix: str) -> Response:
    """
    Generates a multi-sheet Excel for API Discovery results.
    """
    output = io.BytesIO()
    
    # Check if data is empty or None
    if not data:
        data = {}

    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        # Sheet 1: Definitions
        definitions = data.get("definitions_found", [])
        if definitions:
             df_def = pd.DataFrame(definitions)
             df_def.to_excel(writer, index=False, sheet_name='Definitions')
        else:
             pd.DataFrame({"Info": ["No definitions found"]}).to_excel(writer, index=False, sheet_name='Definitions')

        # Sheet 2: Prefixes
        prefixes = data.get("prefixes_found", [])
        if prefixes:
             df_pre = pd.DataFrame(prefixes)
             df_pre.to_excel(writer, index=False, sheet_name='Prefixes')
        else:
             pd.DataFrame({"Info": ["No prefixes found"]}).to_excel(writer, index=False, sheet_name='Prefixes')

        # Sheet 3: Endpoints
        endpoints = data.get("endpoints", [])
        if endpoints:
             # Endpoints is a list of strings
             df_end = pd.DataFrame(endpoints, columns=["Endpoint"])
             df_end.to_excel(writer, index=False, sheet_name='Endpoints')
        else:
             pd.DataFrame({"Info": ["No endpoints found"]}).to_excel(writer, index=False, sheet_name='Endpoints')

    output.seek(0)
    filename = f"{filename_prefix}_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.xlsx"
    
    return Response(
        content=output.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

def generate_form_excel(data: Dict[str, Any], filename_prefix: str) -> Response:
    """
    Generates a multi-sheet Excel for Form Discovery results.
    """
    output = io.BytesIO()
    if not data: data = {}
    
    forms = data.get("forms", [])
    
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        # Sheet 1: Forms
        if forms:
            # Flatten inputs count for the main sheet
            form_summary = []
            all_inputs = []
            
            for idx, f in enumerate(forms):
                form_summary.append({
                    "Form Index": idx + 1,
                    "Action": f.get("action_absolute"),
                    "Original Action": f.get("action"),
                    "Method": f.get("method"),
                    "ID": f.get("id"),
                    "Class": f.get("class"),
                    "Input Count": len(f.get("inputs", []))
                })
                
                # Sheet 2 Prep: Inputs
                for field in f.get("inputs", []):
                    all_inputs.append({
                        "Form Index": idx + 1,
                        "Tag": field.get("tag"),
                        "Name": field.get("name"),
                        "Type": field.get("type"),
                        "ID": field.get("id")
                    })
            
            pd.DataFrame(form_summary).to_excel(writer, index=False, sheet_name='Forms')
            
            if all_inputs:
                pd.DataFrame(all_inputs).to_excel(writer, index=False, sheet_name='Inputs')
            else:
                 pd.DataFrame({"Info": ["No inputs found"]}).to_excel(writer, index=False, sheet_name='Inputs')
        else:
             pd.DataFrame({"Info": ["No forms found"]}).to_excel(writer, index=False, sheet_name='Forms')

    output.seek(0)
    filename = f"{filename_prefix}_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.xlsx"
    
    return Response(
        content=output.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

class PDFReport(FPDF):
    def __init__(self, title):
        super().__init__()
        self.report_title = title
        
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, self.report_title, 0, 1, 'C')
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_pdf(data: List[Dict[str, Any]], title: str, filename_prefix: str, orientation='P') -> Response:
    """
    Generates a PDF file with a simple table from a list of dictionaries.
    """
    pdf = PDFReport(title)
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page(orientation=orientation)
    pdf.set_font("Arial", size=10)
    
    if not data:
        pdf.cell(0, 10, "No data available.", 0, 1)
    else:
        # Simple Table Logic
        # 1. Determine columns from first item
        columns = list(data[0].keys())
        
        # Calculate column widths (naive)
        page_width = pdf.w - 20
        col_width = page_width / len(columns)
        
        # Header
        pdf.set_font("Arial", 'B', 10)
        for col in columns:
            pdf.cell(col_width, 10, str(col).upper(), 1, 0, 'C')
        pdf.ln()
        
        # Rows
        pdf.set_font("Arial", size=9)
        for row in data:
            # 1. Calculate the maximum height needed for this row
            row_heights = []
            for col in columns:
                val = str(row.get(col, ""))
                # Calculate how many lines this value will take
                # nb_lines = pdf.get_nb_lines(col_width, val) # Not always available in all FPDF versions
                # A safe way: use multi_cell with split_only=True if available, or just estimate.
                # In fpdf2, we can use multi_cell and it returns the height if we don't draw?
                # Actually, simpler: just use MultiCell for each and fix the Y.
                pass

            # Calculate the max height for the row (naive estimation or actual check)
            # For simplicity and robustness across FPDF versions, we'll use a fixed height multi_cell
            # and then jump back up to draw the next column.
            
            x_start = pdf.get_x()
            y_start = pdf.get_y()
            max_y = y_start

            for col in columns:
                val = str(row.get(col, ""))
                pdf.multi_cell(col_width, 8, val, border=1, align='L', new_x="RIGHT", new_y="TOP")
                if pdf.get_y() > max_y:
                    max_y = pdf.get_y()
            
            # Reset to the start of the next row
            pdf.set_xy(x_start, max_y)

    output = bytes(pdf.output())

    filename = f"{filename_prefix}_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.pdf"

    return Response(
        content=output,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

def _safe_cell(value: Any, max_len: int = 500) -> str:
    """Sanitize a value for Excel: printable ASCII only, truncated."""
    s = json.dumps(value) if isinstance(value, dict) else str(value) if value is not None else ""
    # Strip non-printable / non-ASCII characters
    s = "".join(c for c in s if c.isprintable() and ord(c) < 128)
    return s[:max_len]


def generate_traffic_excel(data: List[Any], filename_prefix: str) -> Response:
    """
    Specifically handles HTTPTraffic objects for Excel export.
    """
    rows = []
    for t in data:
        rows.append({
            "Timestamp": t.timestamp.strftime('%Y-%m-%d %H:%M:%S') if hasattr(t, 'timestamp') else "",
            "Method": t.method,
            "URL": t.url,
            "Status": t.status_code,
            "Duration (s)": t.duration,
            "Request Headers": _safe_cell(t.request_headers),
            "Response Headers": _safe_cell(t.response_headers),
            "Body Snippet": _safe_cell(t.response_body_snippet),
        })

    return generate_excel(rows, filename_prefix)

def generate_traffic_pdf(data: List[Any], target_domain: str, filename_prefix: str) -> Response:
    """
    Generates a PDF report for HTTP Traffic.
    """
    pdf = PDFReport(f"HTTP Traffic Report: {target_domain}")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page(orientation='L') # Landscape for traffic
    pdf.set_font("Arial", size=10)
    
    if not data:
        pdf.cell(0, 10, "No traffic data available.", 0, 1)
    else:
        # Table Header
        pdf.set_fill_color(240, 240, 240)
        pdf.set_font("Arial", 'B', 9)
        cols = [
            ("Time", 35),
            ("Method", 15),
            ("Status", 15),
            ("Duration", 15),
            ("URL", 190)
        ]
        
        for name, width in cols:
            pdf.cell(width, 10, name, 1, 0, 'C', fill=True)
        pdf.ln()
        
        # Rows
        pdf.set_font("Arial", size=8)
        for t in data:
            # URL can be long, we use cell with truncation or MultiCell?
            # For a log table, cell with truncation is usually cleaner.
            pdf.cell(35, 8, t.timestamp.strftime('%H:%M:%S') if hasattr(t, 'timestamp') else "", 1, 0, 'C')
            pdf.cell(15, 8, str(t.method), 1, 0, 'C')
            pdf.cell(15, 8, str(t.status_code), 1, 0, 'C')
            pdf.cell(15, 8, f"{t.duration}s", 1, 0, 'C')
            
            url_display = t.url
            if len(url_display) > 100:
                url_display = url_display[:97] + "..."
            pdf.cell(190, 8, url_display, 1, 0, 'L')
            pdf.ln()

    output = bytes(pdf.output())
    filename = f"{filename_prefix}_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.pdf"

    return Response(
        content=output,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
