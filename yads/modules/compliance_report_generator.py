"""
Compliance Report Generator

Generates PDF and CSV reports for compliance assessments.
"""

from fpdf import FPDF
from typing import Dict, Any, List
from datetime import datetime


class CompliancePDFReport(FPDF):
    """PDF report generator for compliance assessments."""

    def __init__(self, framework: str, framework_name: str, tenant_name: str):
        super().__init__()
        self.framework = framework
        self.framework_name = framework_name
        self.tenant_name = tenant_name
        self.set_auto_page_break(auto=True, margin=15)
        self.add_page()

    def header(self):
        self.set_font('helvetica', 'B', 18)
        self.cell(0, 10, f'{self.framework_name} Compliance Report', border=False, new_x="LMARGIN", new_y="NEXT", align='L')
        self.set_font('helvetica', '', 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 5, f'Tenant: {self.tenant_name} | Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}', new_x="LMARGIN", new_y="NEXT", align='L')
        self.set_text_color(0, 0, 0)
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'YADS Compliance Report - Page {self.page_no()} - Confidential', align='C')

    def add_executive_summary(self, stats: Dict[str, Any]):
        """Add executive summary section."""
        self.set_font('helvetica', 'B', 14)
        self.set_fill_color(240, 240, 240)
        self.cell(0, 10, 'Executive Summary', new_x="LMARGIN", new_y="NEXT", fill=True)
        self.ln(4)

        score = stats.get('score', 100)
        grade = stats.get('grade', 'A')
        passing = stats.get('passing_controls', 0)
        failing = stats.get('failing_controls', 0)
        total_findings = len(stats.get('findings', []))

        # Score Box
        self.set_font('helvetica', 'B', 24)
        if score >= 90:
            self.set_text_color(16, 185, 129)  # Green
        elif score >= 70:
            self.set_text_color(245, 158, 11)  # Amber
        else:
            self.set_text_color(239, 68, 68)  # Red

        self.cell(60, 20, f'{score}%', border=1, align='C')

        self.set_font('helvetica', 'B', 16)
        self.cell(30, 20, f'Grade {grade}', border=1, align='C')
        self.set_text_color(0, 0, 0)
        self.ln()

        # Stats Grid
        self.ln(4)
        self.set_font('helvetica', '', 11)

        # Row 1
        self.cell(60, 8, f'Controls Passing: {passing}', border=1)
        self.cell(60, 8, f'Controls Failing: {failing}', border=1)
        self.cell(60, 8, f'Total Findings: {total_findings}', border=1)
        self.ln()

        # Compliance Status
        self.ln(4)
        self.set_font('helvetica', 'I', 10)
        if score >= 90:
            self.cell(0, 6, 'Status: COMPLIANT - All major controls pass with minor recommendations.')
        elif score >= 70:
            self.cell(0, 6, 'Status: PARTIAL COMPLIANCE - Some controls require attention.')
        else:
            self.cell(0, 6, 'Status: NON-COMPLIANT - Critical controls failing, immediate action required.')
        self.ln(8)

    def add_control_breakdown(self, breakdown: Dict[str, Any]):
        """Add control-by-control breakdown."""
        self.set_font('helvetica', 'B', 14)
        self.set_fill_color(240, 240, 240)
        self.cell(0, 10, 'Control Breakdown', new_x="LMARGIN", new_y="NEXT", fill=True)
        self.ln(4)

        # Table Header (Total: 185)
        self.set_font('helvetica', 'B', 10)
        self.set_fill_color(230, 230, 230)
        self.cell(25, 8, 'Control', border=1, fill=True)
        self.cell(55, 8, 'Name', border=1, fill=True)
        self.cell(20, 8, 'Status', border=1, fill=True)
        self.cell(25, 8, 'Deduction', border=1, fill=True)
        self.cell(60, 8, 'Issues', border=1, fill=True)
        self.ln()

        self.set_font('helvetica', '', 9)

        for control_id, data in breakdown.items():
            status = data.get('status', 'PASS')
            name = data.get('name', '')[:35]
            deduction = data.get('deduction', 0)
            issues_count = len(data.get('issues', []))

            # Color code status
            if status == 'PASS':
                self.set_text_color(16, 185, 129)
            else:
                self.set_text_color(239, 68, 68)

            self.cell(25, 8, control_id, border=1)
            self.set_text_color(0, 0, 0)
            self.cell(55, 8, name, border=1)

            if status == 'PASS':
                self.set_text_color(16, 185, 129)
            else:
                self.set_text_color(239, 68, 68)
            self.cell(20, 8, status, border=1, align='C')

            self.set_text_color(0, 0, 0)
            self.cell(25, 8, f'-{deduction}', border=1, align='C')
            self.cell(60, 8, f'{issues_count} issue(s)' if issues_count > 0 else 'None', border=1)
            self.ln()

        self.ln(4)

    def add_per_target_breakdown(self, per_target: List[Dict]):
        """Add per-target compliance breakdown."""
        self.add_page()
        self.set_font('helvetica', 'B', 14)
        self.set_fill_color(240, 240, 240)
        self.cell(0, 10, 'Per-Asset Compliance', new_x="LMARGIN", new_y="NEXT", fill=True)
        self.ln(4)

        if not per_target:
            self.set_font('helvetica', 'I', 10)
            self.cell(0, 8, 'No targets assessed.')
            return

        # Table Header (Total: 185)
        self.set_font('helvetica', 'B', 10)
        self.set_fill_color(230, 230, 230)
        self.cell(65, 8, 'Domain', border=1, fill=True)
        self.cell(20, 8, 'Score', border=1, fill=True, align='C')
        self.cell(20, 8, 'Grade', border=1, fill=True, align='C')
        self.cell(25, 8, 'Passing', border=1, fill=True, align='C')
        self.cell(25, 8, 'Failing', border=1, fill=True, align='C')
        self.cell(30, 8, 'Findings', border=1, fill=True, align='C')
        self.ln()

        self.set_font('helvetica', '', 9)

        # Sort by score (worst first)
        sorted_targets = sorted(per_target, key=lambda x: x.get('score', 100))

        for target in sorted_targets[:50]:  # Limit to 50 for report
            domain = target.get('domain', '')[:40]
            score = target.get('score', 100)
            grade = target.get('grade', 'A')
            passing = target.get('passing', 0)
            failing = target.get('failing', 0)
            findings_count = len(target.get('findings', []))

            self.cell(65, 7, domain, border=1)

            # Color code score
            if score >= 90:
                self.set_text_color(16, 185, 129)
            elif score >= 70:
                self.set_text_color(245, 158, 11)
            else:
                self.set_text_color(239, 68, 68)

            self.cell(20, 7, f'{score}%', border=1, align='C')

            # Grade color
            if grade == 'A':
                self.set_text_color(16, 185, 129)
            elif grade in ['B', 'C']:
                self.set_text_color(245, 158, 11)
            else:
                self.set_text_color(239, 68, 68)

            self.cell(20, 7, grade, border=1, align='C')
            self.set_text_color(0, 0, 0)

            self.cell(25, 7, str(passing), border=1, align='C')
            self.cell(25, 7, str(failing), border=1, align='C')
            self.cell(30, 7, str(findings_count), border=1, align='C')
            self.ln()

        self.ln(4)

    def add_findings_detail(self, findings: List[Dict]):
        """Add detailed findings section."""
        self.add_page()
        self.set_font('helvetica', 'B', 14)
        self.set_fill_color(240, 240, 240)
        self.cell(0, 10, 'Detailed Findings', new_x="LMARGIN", new_y="NEXT", fill=True)
        self.ln(4)

        if not findings:
            self.set_font('helvetica', 'I', 10)
            self.cell(0, 8, 'No findings detected. All controls pass.')
            return

        # Group by severity
        critical = [f for f in findings if f.get('severity') == 'critical']
        high = [f for f in findings if f.get('severity') == 'high']
        medium = [f for f in findings if f.get('severity') == 'medium']
        low = [f for f in findings if f.get('severity') == 'low']

        for severity, items, color in [
            ('Critical', critical, (239, 68, 68)),
            ('High', high, (245, 158, 11)),
            ('Medium', medium, (59, 130, 246)),
            ('Low', low, (107, 114, 128))
        ]:
            if not items:
                continue

            self.set_font('helvetica', 'B', 11)
            self.set_text_color(*color)
            self.cell(0, 8, f'{severity} Severity ({len(items)} findings)', new_x="LMARGIN", new_y="NEXT")
            self.set_text_color(0, 0, 0)

            self.set_font('helvetica', '', 9)
            for finding in items[:20]:  # Limit per severity
                control_id = finding.get('control_id', 'N/A')
                desc = finding.get('description', '')[:100]
                deduction = finding.get('deduction', 0)

                self.cell(0, 6, f'  [{control_id}] {desc} (-{deduction}pts)', new_x="LMARGIN", new_y="NEXT")

            if len(items) > 20:
                self.cell(0, 6, f'  ... and {len(items) - 20} more', new_x="LMARGIN", new_y="NEXT")

            self.ln(2)

    def add_remediation_tasks(self, tasks: List):
        """Add remediation tasks section."""
        self.add_page()
        self.set_font('helvetica', 'B', 14)
        self.set_fill_color(240, 240, 240)
        self.cell(0, 10, 'Remediation Tasks', new_x="LMARGIN", new_y="NEXT", fill=True)
        self.ln(4)

        if not tasks:
            self.set_font('helvetica', 'I', 10)
            self.cell(0, 8, 'No active remediation tasks.')
            return

        # Table Header (Total: 185)
        self.set_font('helvetica', 'B', 10)
        self.set_fill_color(230, 230, 230)
        self.cell(55, 8, 'Task', border=1, fill=True)
        self.cell(25, 8, 'Control', border=1, fill=True, align='C')
        self.cell(25, 8, 'Priority', border=1, fill=True, align='C')
        self.cell(25, 8, 'Status', border=1, fill=True, align='C')
        self.cell(30, 8, 'Due Date', border=1, fill=True, align='C')
        self.cell(25, 8, 'SLA', border=1, fill=True, align='C')
        self.ln()

        self.set_font('helvetica', '', 9)

        for task in tasks:
            title = task.title[:35] if hasattr(task, 'title') else str(task.get('title', ''))[:35]
            control_id = task.control_id if hasattr(task, 'control_id') else task.get('control_id', '')
            priority = task.priority if hasattr(task, 'priority') else task.get('priority', 'medium')
            status = task.status if hasattr(task, 'status') else task.get('status', 'open')
            due_date = task.due_date if hasattr(task, 'due_date') else task.get('due_date')
            sla_breached = task.sla_breached if hasattr(task, 'sla_breached') else task.get('sla_breached', False)

            self.cell(55, 7, title, border=1)
            self.cell(25, 7, control_id, border=1, align='C')

            # Priority color
            if priority == 'critical':
                self.set_text_color(239, 68, 68)
            elif priority == 'high':
                self.set_text_color(245, 158, 11)
            else:
                self.set_text_color(0, 0, 0)
            self.cell(25, 7, priority.upper(), border=1, align='C')
            self.set_text_color(0, 0, 0)

            self.cell(25, 7, status.replace('_', ' ').title(), border=1, align='C')

            due_str = due_date.strftime('%Y-%m-%d') if due_date else '-'
            self.cell(30, 7, due_str, border=1, align='C')

            if sla_breached:
                self.set_text_color(239, 68, 68)
                self.cell(25, 7, 'BREACHED', border=1, align='C')
            else:
                self.set_text_color(16, 185, 129)
                self.cell(25, 7, 'OK', border=1, align='C')
            self.set_text_color(0, 0, 0)
            self.ln()

        self.ln(4)

    def add_recommendations(self, stats: Dict[str, Any]):
        """Add recommendations section."""
        self.add_page()
        self.set_font('helvetica', 'B', 14)
        self.set_fill_color(240, 240, 240)
        self.cell(0, 10, 'Recommendations', new_x="LMARGIN", new_y="NEXT", fill=True)
        self.ln(4)

        score = stats.get('score', 100)
        findings = stats.get('findings', [])

        self.set_font('helvetica', '', 10)

        # General recommendations based on score (Width 180 for safety)
        if score < 70:
            self.multi_cell(180, 6, '1. CRITICAL: Address all critical and high severity findings immediately.')
            self.multi_cell(180, 6, '2. Implement a formal vulnerability management program with SLAs.')
            self.multi_cell(180, 6, '3. Consider engaging a security consultant for remediation guidance.')
            self.multi_cell(180, 6, '4. Review and update security policies and procedures.')
        elif score < 90:
            self.multi_cell(180, 6, '1. Address remaining high severity findings within 30 days.')
            self.multi_cell(180, 6, '2. Implement missing security headers and TLS best practices.')
            self.multi_cell(180, 6, '3. Review exposed services and restrict access where possible.')
            self.multi_cell(180, 6, '4. Establish regular compliance monitoring cadence.')
        else:
            self.multi_cell(180, 6, '1. Maintain current security posture with regular assessments.')
            self.multi_cell(180, 6, '2. Address remaining low severity findings as time permits.')
            self.multi_cell(180, 6, '3. Consider obtaining formal compliance certification.')
            self.multi_cell(180, 6, '4. Document security controls for audit purposes.')

        self.ln(4)

        # Specific recommendations based on findings
        self.set_font('helvetica', 'B', 11)
        self.cell(0, 8, 'Priority Actions:', new_x="LMARGIN", new_y="NEXT")
        self.set_font('helvetica', '', 10)

        seen_controls = set()
        for finding in findings[:10]:
            control_id = finding.get('control_id', '')
            if control_id in seen_controls:
                continue
            seen_controls.add(control_id)

            control_name = finding.get('control_name', '')
            self.multi_cell(0, 6, f'- {control_id}: Remediate {control_name} control failures.')


def generate_compliance_report(
    framework: str,
    framework_name: str,
    overall_stats: Dict[str, Any],
    per_target: List[Dict],
    remediation_tasks: List,
    tenant_name: str = "Global"
) -> bytes:
    """
    Generate a comprehensive compliance PDF report.

    Args:
        framework: Framework ID (e.g., 'soc2')
        framework_name: Framework display name (e.g., 'SOC2')
        overall_stats: Overall compliance statistics
        per_target: Per-target compliance breakdown
        remediation_tasks: List of remediation tasks
        tenant_name: Tenant name for the report

    Returns:
        PDF content as bytes
    """
    pdf = CompliancePDFReport(framework, framework_name, tenant_name)

    # Add sections
    pdf.add_executive_summary(overall_stats)
    pdf.add_control_breakdown(overall_stats.get('detailed_breakdown', {}))
    pdf.add_per_target_breakdown(per_target)
    pdf.add_findings_detail(overall_stats.get('findings', []))
    pdf.add_remediation_tasks(remediation_tasks)
    pdf.add_recommendations(overall_stats)

    return pdf.output()
