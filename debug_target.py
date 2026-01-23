#!/usr/bin/env python3
import sys
sys.path.insert(0, '/app')

print("Starting...", flush=True)

from sqlmodel import select, Session, create_engine
from yads.models import Target, ScanResult, ScanSchedule, SystemConfig, User
from yads.config import settings
from yads.core.compliance import calculate_security_grade, generate_compliance_report
from fastapi.templating import Jinja2Templates
from fastapi.encoders import jsonable_encoder
import jinja2

print("Imports done", flush=True)

engine = create_engine(settings.DATABASE_URL)

# Custom filters from main.py
def tojson_filter(value):
    import json
    return json.dumps(value) if value is not None else 'null'

templates = Jinja2Templates(directory='/app/yads/api/templates')
templates.env.filters['tojson'] = tojson_filter

class FakeRequest:
    class FakeURL:
        path = '/targets/24234'
    url = FakeURL()
    
with Session(engine) as session:
    target_id = 24234
    user = session.exec(select(User).where(User.username == 'admin')).first()
    target = session.exec(select(Target).where(Target.id == target_id, Target.tenant_id == user.tenant_id)).first()
    
    print(f"Target: {target.domain if target else 'None'}", flush=True)
    
    history_entries = session.exec(select(ScanResult).where(ScanResult.target_id == target_id).order_by(ScanResult.scanned_at.desc()).limit(50)).all()
    
    # Extract results
    latest_subdomain = next((r for r in history_entries if r.module_name == 'subdomain_scanner'), None)
    dns_only_result = next((r for r in history_entries if r.module_name == 'dns_scanner'), None)
    dns_result = latest_subdomain if latest_subdomain else dns_only_result
    web_result = next((r for r in history_entries if r.module_name == 'web_analyzer'), None)
    typosquat_result = next((r for r in history_entries if r.module_name == 'typosquat_scanner'), None)
    infra_result = next((r for r in history_entries if r.module_name == 'infrastructure_scanner'), None)
    visual_result = next((r for r in history_entries if r.module_name == 'visual_osint'), None)
    ssl_result = next((r for r in history_entries if r.module_name == 'ssl_scanner'), None)
    wayback_result = next((r for r in history_entries if r.module_name == 'wayback_scanner'), None)
    crawler_result = next((r for r in history_entries if r.module_name == 'crawler'), None)
    content_discovery_result = next((r for r in history_entries if r.module_name == 'content_discovery'), None)
    tld_result = next((r for r in history_entries if r.module_name == 'tld_scanner'), None)
    port_result = next((r for r in history_entries if r.module_name == 'port_scanner'), None)
    nmap_result = next((r for r in history_entries if r.module_name == 'nmap_scanner'), None)
    nuclei_result = next((r for r in history_entries if r.module_name == 'nuclei_scanner'), None)
    
    current_results = [r for r in [latest_subdomain, dns_only_result, web_result, typosquat_result, infra_result, visual_result, ssl_result, wayback_result, crawler_result, content_discovery_result, tld_result, port_result, nmap_result, nuclei_result] if r]

    print(f"Results: {len(current_results)}", flush=True)
    
    # Compliance & Grading
    comp_input = {
        "web_result": web_result,
        "ssl_result": ssl_result,
        "nmap_result": nmap_result,
        "nuclei_result": nuclei_result,
        "port_result": port_result
    }
    security_grade = calculate_security_grade(comp_input)
    compliance_report = generate_compliance_report(comp_input)
    
    print(f"Compliance done", flush=True)

    # Cipher Compliance Setup
    approved_ciphers_set = set()
    schedule = session.exec(select(ScanSchedule).where(ScanSchedule.target_id == target_id)).first()

    context = {
        "user": user,
        "request": FakeRequest(),
        "target": target,
        "dns_result": dns_result,
        "web_result": web_result,
        "typosquat_result": typosquat_result,
        "infra_result": infra_result,
        "visual_result": visual_result,
        "ssl_result": ssl_result,
        "wayback_result": wayback_result,
        "crawler_result": crawler_result,
        "content_discovery_result": content_discovery_result,
        "tld_result": tld_result,
        "port_result": port_result,
        "nmap_result": nmap_result,
        "nuclei_result": nuclei_result,
        "security_grade": security_grade,
        "compliance_report": compliance_report,
        "history_entries": history_entries,
        "current_history_id": None,
        "raw_results": jsonable_encoder([r.model_dump() for r in current_results]),
        "approved_ciphers": approved_ciphers_set,
        "schedule": schedule,
        "settings": settings
    }
    
    print("Attempting template render...", flush=True)
    try:
        template = templates.get_template("target_detail.html")
        output = template.render(context)
        print(f"SUCCESS! Rendered {len(output)} chars", flush=True)
    except Exception as e:
        print(f"TEMPLATE ERROR: {type(e).__name__}: {e}", flush=True)
        import traceback
        traceback.print_exc()
