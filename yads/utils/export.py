
import io
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
            for col in columns:
                # Truncate content to fit naive width or handle multiline (too complex for basics, truncating for now)
                val = str(row.get(col, ""))
                
                # Check string length - very rough heuristic
                # FPDF cell handles text, but won't wrap automatically with 'cell', need 'multi_cell' for that.
                # For simplicity in this iteration, we use cell and clip.
                # A better approach for specific reports is to custom build the PDF in the router using this helper as a base,
                # but let's try to make this generic enough for the requirements.
                
                # Handling extremely long text
                if len(val) > 20 and len(columns) > 4:
                     val = val[:17] + "..."
                elif len(val) > 50:
                     val = val[:47] + "..."
                     
                pdf.cell(col_width, 10, val, 1, 0, 'L')
            pdf.ln()

    output = pdf.output(dest='S').encode('latin-1') # fpdf2 output to string, encode to bytes
    
    filename = f"{filename_prefix}_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.pdf"
    
    return Response(
        content=output,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
