#!/usr/bin/env python3
"""Test report templates against a customer data"""

import sys
import re
sys.path.insert(0, "/app")

from sqlmodel import Session, select
from yads.database import engine
from yads.models import Target, Tenant, ScanResult
from yads.api.routers.report_builder import gather_scan_data
from yads.core.markdown_report_generator import render_markdown_with_data

TEMPLATES = {
    "complete": "/app/report_templates/customer_complete_assessment.md",
    "executive": "/app/report_templates/customer_executive_summary.md",
    "vulnerability": "/app/report_templates/customer_vulnerability_report.md",
    "ssl": "/app/report_templates/customer_ssl_certificate_report.md",
    "infrastructure": "/app/report_templates/customer_infrastructure_inventory.md",
}


def main():
    with Session(engine) as session:
        # Get a customer tenant
        tenant = session.exec(select(Tenant).where(Tenant.name == "a customer")).first()
        if not tenant:
            print("ERROR: a customer tenant not found")
            return

        print(f"Tenant: {tenant.name} (ID: {tenant.id})")

        # Get targets with scan data
        targets = session.exec(
            select(Target)
            .where(Target.tenant_id == tenant.id)
            .where(Target.is_archived == False)
            .limit(3)
        ).all()

        if not targets:
            print("ERROR: No targets found")
            return

        target_ids = [t.id for t in targets]
        print(f"Targets: {[t.domain for t in targets]}")

        # Gather and normalize data
        scan_data = gather_scan_data(session, target_ids, tenant.id)
        print(f"\nData gathered: {len(scan_data['targets'])} targets")
        print(f"Summary: {scan_data['summary']}")

        if scan_data["targets"]:
            t0 = scan_data["targets"][0]
            modules = list(t0["modules"].keys())
            print(f"Modules for {t0['domain']}: {modules}")

            # Verify normalization worked
            print("\n--- Normalization Check ---")

            if "ssl_scanner" in t0["modules"]:
                ssl = t0["modules"]["ssl_scanner"]
                print(f"SSL not_after: {ssl.get('not_after', 'MISSING')}")
                print(f"SSL not_before: {ssl.get('not_before', 'MISSING')}")
                print(f"SSL issuer (normalized): {str(ssl.get('issuer', 'MISSING'))[:60]}")
                print(f"SSL subject_alt_names: {ssl.get('subject_alt_names', 'MISSING')}")
                print(f"SSL days_until_expiry: {ssl.get('days_until_expiry', 'MISSING')}")
                print(f"SSL is_valid: {ssl.get('is_valid', 'MISSING')}")
                print(f"SSL protocols: {ssl.get('protocols', 'MISSING')}")
            else:
                print("SSL scanner: No data")

            if "web_analyzer" in t0["modules"]:
                web = t0["modules"]["web_analyzer"]
                sec_headers = web.get("security_headers", {})
                print(f"Web security_headers: {list(sec_headers.keys())}")
                print(f"Web missing_headers: {web.get('missing_headers', 'MISSING')}")
                print(f"Web tech_stack: {web.get('tech_stack', 'MISSING')}")
            else:
                print("Web analyzer: No data")

            if "dns_scanner" in t0["modules"]:
                dns = t0["modules"]["dns_scanner"]
                print(f"DNS subdomains count: {len(dns.get('subdomains', []))}")
                print(f"DNS records.A: {dns.get('records', {}).get('A', 'MISSING')}")
            else:
                print("DNS scanner: No data")

        # Test each template
        print("\n" + "=" * 60)
        print("TEMPLATE RENDERING TESTS")
        print("=" * 60)

        results = []
        for name, path in TEMPLATES.items():
            try:
                with open(path, "r") as f:
                    content = f.read()

                html = render_markdown_with_data(content, scan_data, tenant)

                # Analyze result
                unrendered = re.findall(r"\{\{[^}]+\}\}", html)
                no_data_count = html.count("*No ") + html.count("*no ")

                status = "PASS"
                notes = []

                if unrendered:
                    status = "WARN"
                    notes.append(f"{len(unrendered)} unrendered")
                if no_data_count > 15:
                    notes.append(f"{no_data_count} empty sections")

                note_str = f" ({', '.join(notes)})" if notes else ""
                print(f"[{status}] {name}: {len(html):,} chars{note_str}")

                results.append((name, status, len(html), notes))

            except Exception as e:
                print(f"[FAIL] {name}: {e}")
                import traceback
                traceback.print_exc()
                results.append((name, "FAIL", 0, [str(e)]))

        # Summary
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        passed = sum(1 for _, s, _, _ in results if s == "PASS")
        warned = sum(1 for _, s, _, _ in results if s == "WARN")
        failed = sum(1 for _, s, _, _ in results if s == "FAIL")
        print(f"PASS: {passed}, WARN: {warned}, FAIL: {failed}")

        if failed == 0:
            print("\nAll templates rendered successfully!")


if __name__ == "__main__":
    main()
