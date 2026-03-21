from typing import List, Optional
from fastapi import APIRouter, Depends, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select
import random
import os
import string
from datetime import datetime, timezone
import logging

# Setup Logger
logger = logging.getLogger("yads-api")

from yads.database import get_session
from yads.models import User, Target, Tenant, OSINTIntelligence
from yads.auth.deps import get_current_user_html, RoleChecker, get_current_user
from yads.config import settings
from yads.utils.license_deps import require_feature

# Google API Config (Mock/Stub for now)
GOOGLE_SEARCH_API_KEY = os.getenv("GOOGLE_SEARCH_API_KEY")
GOOGLE_SEARCH_CX = os.getenv("GOOGLE_SEARCH_CX")

router = APIRouter(prefix="/osint", tags=["osint"], dependencies=[Depends(require_feature("osint"))])
from yads.api.templating import templates

# Inject Globals (Required for base.html)
templates.env.globals['settings'] = settings
templates.env.globals['now_utc'] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

def get_all_tenants():
    # Helper to fetch all tenants for Platform Admin dropdown
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import Tenant
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()

templates.env.globals['get_available_tenants'] = get_all_tenants

# Mock Search Results Generator
def mock_reverse_image_search(filename: str) -> List[dict]:
    """
    Simulates finding domains based on an uploaded logo.
    """
    # ... code ...
    seed = len(filename)
    random.seed(seed)
    # ...
    # (Rest of mock function logic remains, this is just to anchor the next function)
    found_domains = []
    common_tlds = [".com", ".net", ".org", ".io", ".de"]
    prefixes = ["brand", "shop", "login", "secure", "dev", "staging", "old", "mail"]
    base_names = ["example", "demo", "test", "mybrand", "corporation"]
    num_results = random.randint(3, 8)
    for _ in range(num_results):
        prefix = random.choice(prefixes)
        base = random.choice(base_names)
        tld = random.choice(common_tlds)
        domain = f"{prefix}-{base}{tld}"
        found_domains.append({
            "domain": domain,
            "type": "Mock Result",
            "confidence": "Low",
            "url": f"http://{domain}"
        })
    return found_domains

import requests

import base64

def google_vision_search(file_content: bytes, api_key: str) -> List[dict]:
    """
    Executes Google Cloud Vision API Web Detection.
    """
    logger.info(f"DEBUG: Executing Vision API Web Detection")
    url = f"https://vision.googleapis.com/v1/images:annotate?key={api_key}"
    
    # Base64 encode image
    encoded_image = base64.b64encode(file_content).decode("utf-8")
    
    payload = {
        "requests": [
            {
                "image": {
                    "content": encoded_image
                },
                "features": [
                    {
                        "type": "WEB_DETECTION",
                        "maxResults": 10
                    }
                ]
            }
        ]
    }
    
    try:
        resp = requests.post(url, json=payload, timeout=20)
        logger.info(f"DEBUG: Vision API Status Code: {resp.status_code}")
        
        # Log raw response for debugging (truncated to avoid massive logs if successful)
        resp_text = resp.text
        logger.info(f"DEBUG: Vision API Raw Response: {resp_text[:1000]}")
        
        resp.raise_for_status()
        data = resp.json()
        
        found = {}

        # Parse Responses
        responses = data.get("responses", [])
        if not responses:
            logger.warning("DEBUG: 'responses' list is empty.")
            return []
            
        first_response = responses[0]
        
        # Check for error in response
        if "error" in first_response:
            error_details = first_response.get("error", {})
            logger.error(f"ERROR: Vision API returned error: {error_details}")
            return []
            
        web_detection = first_response.get("webDetection", {})
        
        # Helper to add results
        def add_result(url, match_type, confidence="High"):
             if url:
                 from urllib.parse import urlparse
                 domain = urlparse(url).netloc.lower()
                 if domain not in found:
                     found[domain] = {
                         "domain": domain,
                         "type": match_type,
                         "confidence": confidence,
                         "url": url
                     }

        # 1. Full Matching Images (Exact matches found on web)
        if "fullMatchingImages" in web_detection:
            count = len(web_detection["fullMatchingImages"])
            logger.info(f"DEBUG: Found {count} fullMatchingImages")
            for item in web_detection["fullMatchingImages"]:
                 add_result(item.get("url"), "Exact Match", "High")
                 
        # 2. Pages with Matching Images
        if "pagesWithMatchingImages" in web_detection:
             count = len(web_detection["pagesWithMatchingImages"])
             logger.info(f"DEBUG: Found {count} pagesWithMatchingImages")
             for item in web_detection["pagesWithMatchingImages"]:
                 add_result(item.get("url"), "Page Match", "High")

        # 3. Partial Matching Images
        if "partialMatchingImages" in web_detection:
             count = len(web_detection["partialMatchingImages"])
             logger.info(f"DEBUG: Found {count} partialMatchingImages")
             for item in web_detection["partialMatchingImages"]:
                 add_result(item.get("url"), "Partial Match", "Medium")

        # 4. Visually Similar Images
        if "visuallySimilarImages" in web_detection:
             count = len(web_detection["visuallySimilarImages"])
             logger.info(f"DEBUG: Found {count} visuallySimilarImages")
             for item in web_detection["visuallySimilarImages"]:
                 add_result(item.get("url"), "Visually Similar", "Low")
        
        logger.info(f"DEBUG: Extracted {len(found)} unique domains.")
        return list(found.values())

    except Exception as e:
        logger.error(f"ERROR: Vision API Search Failed: {str(e)}")
        # If API not enabled or error, return empty
        return []

def google_search_stub(file: UploadFile, api_key: str, cx: str) -> List[dict]:
    """
    Determines whether to use Vision API or Mock.
    NOTE: cx is unused for Vision API but kept for signature compatibility/fallback logic check.
    """
    filename = file.filename
    
    # Check for valid API Key (length check heuristic)
    # Heuristic: If key length > 10, assume valid.
    if api_key and len(api_key) > 5:
        logger.info(f"DEBUG: Switching to VISION API (Web Detection).")
        try:
             # Read file bytes for Vision API
             # Important: file read pointer might need reset if used elsewhere, 
             # but here we consume it.
             content = file.file.read()
             
             # Reset pointer just in case wrapper needs it? 
             # UploadFile is a wrapper.
             file.file.seek(0) 
             
             results = google_vision_search(content, api_key)
             if results:
                 return results
             else:
                 logger.info("DEBUG: Vision API returned no results.")
                 # If no results and we have valid keys, we should probably stop and not fallback to mock.
                 # BUT, for testing, maybe user wants to see *something*? 
                 # Let's return empty to be honest about the search.
                 return [] 
        except Exception as e:
             logger.error(f"ERROR: Reading file for Vision API failed: {e}")
             return []

    logger.info(f"DEBUG: No valid keys found or fallback. Using MOCK.")
    return mock_reverse_image_search(filename)

@router.get("/", response_class=HTMLResponse)
async def osint_page(
    request: Request, 
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))
):
    # License Check
    if user.tenant_id:
        if not user.tenant.osint_enabled:
            return templates.TemplateResponse("osint_blocked.html", {"request": request, "user": user})
            
    # Check for Google Keys (Tenant or System)
    has_google_keys = False
    if (user.tenant and user.tenant.google_api_key and len(user.tenant.google_api_key) > 5) or \
       (GOOGLE_SEARCH_API_KEY and len(GOOGLE_SEARCH_API_KEY) > 5):
        has_google_keys = True

    return templates.TemplateResponse("osint.html", {
        "request": request,
        "user": user,
        "active_tab": "osint",
        "has_google_keys": has_google_keys
    })

@router.post("/search", response_class=HTMLResponse)
async def osint_search(
    request: Request,
    files: List[UploadFile] = File(default=[]), # Default to empty list to handle 422
    test_domain: Optional[str] = Form(None), 
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))
):
    logger.info(f"DEBUG: OSINT Search Request. Files: {len(files)}, TestDomain: {test_domain}")
    
    # Validation: Ensure at least one file or test domain
    has_files = False
    for f in files:
        if f.filename:
            has_files = True
            break
            
    if not has_files and not test_domain:
        return "<div class='text-red-400 p-4 border border-red-800 rounded bg-red-900/20'>Please upload an image or provide a test domain.</div>"

    all_found_domains = {}  # Now a dict: domain -> result_obj
    
    # Check Quota & License
    if user.tenant_id:
        # Re-fetch tenant to ensure fresh state
        tenant = session.get(Tenant, user.tenant_id)
        if not tenant.osint_enabled:
             return "<div class='text-red-400 p-4'>Feature not enabled for this tenant.</div>"
             
        if tenant.osint_quota_used >= tenant.osint_quota_max:
             return f"<div class='text-red-400 p-4 border border-red-800 rounded bg-red-900/20'>Quota Exceeded used ({tenant.osint_quota_used}/{tenant.osint_quota_max}). Please contact admin.</div>"

        # Determine Config (Tenant > System)
        api_key = tenant.google_api_key if tenant.google_api_key else GOOGLE_SEARCH_API_KEY
        cx = tenant.google_cse_cx if tenant.google_cse_cx else GOOGLE_SEARCH_CX
        
        logger.info(f"DEBUG: OSINT Using Key: {'(Tenant)' if tenant.google_api_key else '(System)'}")

        # Increment for this batch
        tenant.osint_quota_used += 1
        session.add(tenant)
        session.commit()
    
    # Process uploads
    for file in files:
        if file.filename:
            logger.info(f"DEBUG: Processing file {file.filename}")
            
            # Use Stub if configured, else Mock
            # Pass the determining configuration
            # Note: google_search_stub now expects 'file' (UploadFile) not 'filename'
            results = google_search_stub(file, api_key, cx)
            
            # Merging results (prioritize higher confidence if duplicate?) 
            # Simple merge: just overwrite for now or checking existence
            for res in results:
                domain = res["domain"]
                if domain not in all_found_domains:
                    all_found_domains[domain] = res
                else:
                    # Update if new result has higher confidence?
                    # Priority: High > Medium > Low
                    current_conf = all_found_domains[domain]["confidence"]
                    new_conf = res["confidence"]
                    if new_conf == "High" and current_conf != "High":
                        all_found_domains[domain] = res
                    elif new_conf == "Medium" and current_conf == "Low":
                        all_found_domains[domain] = res
            
            
    # Add test domain if provided
    if test_domain and test_domain.strip():
        td = test_domain.strip().lower()
        if td not in all_found_domains:
            all_found_domains[td] = {
                "domain": td, 
                "type": "Manual Test", 
                "confidence": "Manual", 
                "url": f"http://{td}"
            }
        
    # Filter against known targets
    # Get all known domains for this tenant
    known_targets = session.exec(select(Target.domain).where(Target.tenant_id == user.tenant_id)).all()
    known_set = set(known_targets)
    
    unknown_domains = []
    already_known = []
    
    # Sort keys for consistent order
    sorted_domains = sorted(all_found_domains.keys())

    for domain in sorted_domains:
        result_obj = all_found_domains[domain]
        if domain in known_set:
            already_known.append(result_obj)
        else:
            unknown_domains.append(result_obj)
            
    return templates.TemplateResponse("_osint_results.html", {
        "request": request,
        "user": user,
        "unknown_domains": unknown_domains,
        "already_known": already_known,
        "total_found": len(all_found_domains)
    })

@router.post("/import", response_class=HTMLResponse)
async def osint_import(
    request: Request,
    selected_domains: List[str] = Form(...),
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))
):
    imported_count = 0
    
    for domain in selected_domains:
        domain = domain.strip().lower()
        if not domain: continue
        
        # Double check existence to be safe
        existing = session.exec(select(Target).where(Target.domain == domain, Target.tenant_id == user.tenant_id)).first()
        if not existing:
            new_target = Target(domain=domain, tenant_id=user.tenant_id, tags=["osint_discovered"])
            session.add(new_target)
            imported_count += 1
            
    session.commit()
    
    # Return success message
    return f"""
    <div class="p-4 mb-4 text-sm text-green-400 rounded-lg bg-green-900/20 border border-green-800" role="alert">
        <span class="font-medium">Success!</span> Imported {imported_count} new targets.
        <a href="/targets/table" class="underline hover:text-green-300 ml-2">View Targets</a>
    </div>
    """

# --- New OSINT Intelligence Endpoints (Evolution Phase 0) ---

@router.get("/target/{target_id}")
def get_osint_for_target(
    target_id: int, 
    module_name: Optional[str] = None,
    session: Session = Depends(get_session),
    _: User = Depends(get_current_user)
):
    """
    Retrieve all structured OSINT intelligence records for a specific target.
    Optionally filter by module_name (e.g., 'leaked_credentials').
    """
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    query = select(OSINTIntelligence).where(OSINTIntelligence.target_id == target_id)
    
    if module_name:
        query = query.where(OSINTIntelligence.module_name == module_name)
        
    records = session.exec(query.order_by(OSINTIntelligence.timestamp.desc())).all()
    return records


@router.get("/target/{target_id}/graph")
def get_osint_graph_data(
    target_id: int, 
    session: Session = Depends(get_session),
    _: User = Depends(get_current_user)
):
    """
    Retrieve OSINT data explicitly formatted for a relationship graph (nodes and edges).
    This serves as the foundation for the Phase 4 Visual Intelligence UI.
    """
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    records = session.exec(
        select(OSINTIntelligence).where(OSINTIntelligence.target_id == target_id)
    ).all()
    
    nodes = [{"id": f"target_{target_id}", "label": target.domain, "type": "target"}]
    edges = []
    
    for record in records:
        node_id = f"{record.data_type}_{record.id}"
        
        # Leaked Credentials
        if record.module_name == "leaked_credentials" and record.data_type == "breach_record":
            breach_name = record.data_json.get("name", "Unknown Breach")
            nodes.append({"id": node_id, "label": f"Breach:\n{breach_name}", "group": "leak"})
            edges.append({"source": f"target_{target_id}", "target": node_id, "label": "found in"})
            
        # Tech Stack
        elif record.data_type == "tech_stack":
            tech_name = record.data_json.get("name", "Tech")
            nodes.append({"id": node_id, "label": f"Tech:\n{tech_name}", "group": "tech"})
            edges.append({"source": f"target_{target_id}", "target": node_id, "label": "runs"})

        # Historical DNS / IPs
        elif record.data_type in ["historical_dns", "historical_ip"]:
            ip = record.data_json.get("ip", "Unknown IP")
            sub = record.data_json.get("subdomain", "")
            label = f"IP:\n{ip}" if not sub else f"Sub:\n{sub}\n({ip})"
            nodes.append({"id": node_id, "label": label, "group": "infrastructure"})
            edges.append({"source": f"target_{target_id}", "target": node_id, "label": "resolved to"})

        # Certificate Transparency
        elif record.data_type == "certificate_transparency":
            sub = record.data_json.get("subdomain", "Unknown")
            nodes.append({"id": node_id, "label": f"Cert:\n{sub}", "group": "certificate"})
            edges.append({"source": f"target_{target_id}", "target": node_id, "label": "issued for"})

        # Social Profiles
        elif record.data_type == "social_profile":
            platform = record.data_json.get("platform", "Social")
            user = record.data_json.get("username", "Unknown")
            nodes.append({"id": node_id, "label": f"{platform.title()}:\n{user}", "group": "social"})
            edges.append({"source": f"target_{target_id}", "target": node_id, "label": "owns profile"})

        # Code Exposure
        elif record.data_type == "code_exposure_leak":
            repo = record.data_json.get("repo_name", "Unknown Repo")
            nodes.append({"id": node_id, "label": f"Exposure:\n{repo}", "group": "leak"})
            edges.append({"source": f"target_{target_id}", "target": node_id, "label": "leaked in"})

        # Cloud Exposure
        elif record.data_type == "cloud_exposure":
            bucket = record.data_json.get("bucket_name", "Bucket")
            nodes.append({"id": node_id, "label": f"Exposed:\n{bucket}", "group": "leak"})
            edges.append({"source": f"target_{target_id}", "target": node_id, "label": "exposes"})

        # Dangling CNAME
        elif record.data_type == "dangling_cname":
            subdomain = record.data_json.get("subdomain", "Subdomain")
            nodes.append({"id": node_id, "label": f"Takeover:\n{subdomain}", "group": "vulnerability"})
            edges.append({"source": f"target_{target_id}", "target": node_id, "label": "vulnerable at"})

        # Document Metadata
        elif record.data_type == "document_metadata":
            author = record.data_json.get("author") or record.data_json.get("creator") or "Unknown Author"
            nodes.append({"id": node_id, "label": f"Author:\n{author}", "group": "identity"})
            edges.append({"source": f"target_{target_id}", "target": node_id, "label": "authored doc"})

        # WHOIS Records
        elif record.data_type == "whois_record":
            registrar = record.data_json.get("registrar", "Unknown Registrar")
            if isinstance(registrar, list): registrar = registrar[0]
            nodes.append({"id": node_id, "label": f"Registrar:\n{registrar}", "group": "domain"})
            edges.append({"source": f"target_{target_id}", "target": node_id, "label": "registered via"})

        # Shodan / Censys Vulnerabilities
        elif record.data_type == "vulnerability":
            cve = record.data_json.get("cve", "CVE")
            nodes.append({"id": node_id, "label": f"CVE:\n{cve}", "group": "leak"})
            edges.append({"source": f"target_{target_id}", "target": node_id, "label": "vulnerable to"})

        # Shodan / Censys Open Ports
        elif record.data_type == "open_port":
            port = record.data_json.get("port", "Port")
            nodes.append({"id": node_id, "label": f"Port:\n{port}", "group": "infrastructure"})
            edges.append({"source": f"target_{target_id}", "target": node_id, "label": "has open"})
            
        # Shodan Tags
        elif record.data_type == "shodan_tag":
            tag = record.data_json.get("tag", "Tag")
            nodes.append({"id": node_id, "label": f"Tag:\n{tag}", "group": "infrastructure"})
            edges.append({"source": f"target_{target_id}", "target": node_id, "label": "tagged as"})

        # Threat Intel Verdicts
        elif record.data_type == "threat_verdict":
            title = record.data_json.get("title", "Threat").split(":")[0]
            nodes.append({"id": node_id, "label": f"Alert:\n{title}", "group": "leak"})
            edges.append({"source": f"target_{target_id}", "target": node_id, "label": "flagged by"})
            
    return {"nodes": nodes, "edges": edges}

@router.post("/refresh/{target_id}")
def refresh_osint_target(
    target_id: int,
    session: Session = Depends(get_session),
    _: User = Depends(get_current_user)
):
    """
    Triggers an immediate OSINT-only scan for the given target using the dedicated 
    high-priority Celery OSINT orchestration task.
    """
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    try:
        from yads.worker_tasks import run_osint_enrichment
        run_osint_enrichment.apply_async(
            args=[target.id, target.domain, target.tenant_id],
            queue="high_priority"
        )
        return {"status": "success", "message": f"OSINT enrichment actively queued for {target.domain}"}
    except Exception as e:
        logger.error(f"Error starting OSINT refresh scan for target {target_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to start OSINT refresh scan")

@router.get("/export-pdf/{target_id}")
def export_osint_pdf(
    target_id: int,
    session: Session = Depends(get_session),
    _: User = Depends(get_current_user)
):
    """Generates and downloads the OSINT Intelligence Dossier."""
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    records = session.exec(
        select(OSINTIntelligence).where(OSINTIntelligence.target_id == target_id)
    ).all()
    
    osint_data = []
    for r in records:
        osint_data.append({
            "data_type": r.data_type,
            "data_json": r.data_json,
            "severity": r.severity,
            "module_name": r.module_name,
            "timestamp": r.timestamp
        })
        
    from yads.modules.report_generator import generate_osint_dossier
    pdf_bytes = generate_osint_dossier(target.domain, osint_data)
    
    from fastapi.responses import Response
    headers = {
        "Content-Disposition": f'attachment; filename="osint_dossier_{target.domain}.pdf"'
    }
    return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)

@router.post("/target/{target_id}/ai-enrich")
async def enrich_osint_with_ai(
    target_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user)
):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    from yads.core.llm_service import load_llm_config, get_osint_analysis
    config = load_llm_config(session, target.tenant_id)
    if config.get("LLM_PROVIDER", "disabled").lower() == "disabled":
        raise HTTPException(status_code=400, detail="LLM Provider is not configured or disabled.")
        
    records = session.exec(
        select(OSINTIntelligence).where(OSINTIntelligence.target_id == target_id)
    ).all()
    
    osint_data = []
    for r in records:
        if r.data_type == "ai_summary": continue
        osint_data.append({
            "data_type": r.data_type,
            "data_json": r.data_json,
            "severity": r.severity,
            "module_name": r.module_name,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None
        })
        
    if not osint_data:
        raise HTTPException(status_code=400, detail="No OSINT records found to analyze.")
        
    result = await get_osint_analysis(target.domain, osint_data, config)
    if not result:
        raise HTTPException(status_code=500, detail="LLM analysis failed.")
        
    old_summary = session.exec(
        select(OSINTIntelligence).where(
            OSINTIntelligence.target_id == target_id,
            OSINTIntelligence.data_type == "ai_summary"
        )
    ).first()
    if old_summary:
        session.delete(old_summary)
        
    import datetime
    ai_record = OSINTIntelligence(
        target_id=target.id,
        module_name="llm_enrichment",
        data_type="ai_summary",
        data_json=result,
        severity=result.get("risk_rating", "INFO").upper(),
        timestamp=datetime.now(timezone.utc)
    )
    session.add(ai_record)
    session.commit()
    
    return {"status": "success", "message": "OSINT Data successfully analyzed by AI."}
    
@router.get("/target/{target_id}/map", response_class=HTMLResponse)
def get_osint_map_view(
    request: Request,
    target_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html)
):
    """Renders the dedicated Geospatial Infrastructure Map for a target."""
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    return templates.TemplateResponse("osint/map.html", {
        "request": request,
        "user": user,
        "target": target
    })

@router.get("/target/{target_id}/geo-json")
def get_osint_geo_json(
    target_id: int,
    session: Session = Depends(get_session),
    _: User = Depends(get_current_user)
):
    """
    Extracts all infrastructure points (IPs, Subdomains) for a target and 
    returns them as a GeoJSON FeatureCollection with metadata.
    """
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    records = session.exec(
        select(OSINTIntelligence).where(
            OSINTIntelligence.target_id == target_id
        ).order_by(OSINTIntelligence.timestamp.desc())
    ).all()
    
    features = []
    seen_ips = set()
    
    for record in records:
        data = record.data_json
        if not data: continue
        
        # Check for Geo data
        # Locations can come from:
        # 1. infrastructure_scanner (real-time geoip)
        # 2. historical_ip / historical_dns (enriched with geoip in future or already having it)
        geo = data.get("geoip") or {}
        lat = geo.get("lat")
        lon = geo.get("lon")
        
        if lat and lon:
            # Found coordinates
            ip = data.get("ip") or "Unknown IP"
            subdomain = data.get("subdomain") or target.domain
            
            # Use data_type for coloring/icons in frontend
            feature = {
                "type": "Feature",
                "geometry": {
                    "type": "Point",
                    "coordinates": [lon, lat]
                },
                "properties": {
                    "id": record.id,
                    "label": f"{subdomain} ({ip})",
                    "ip": ip,
                    "subdomain": subdomain,
                    "data_type": record.data_type,
                    "severity": record.severity,
                    "city": geo.get("city", "Unknown"),
                    "country": geo.get("country_name", "Unknown"),
                    "timestamp": record.timestamp.isoformat() if record.timestamp else None
                }
            }
            features.append(feature)
            if ip != "Unknown IP":
                seen_ips.add(ip)
                
    return {
        "type": "FeatureCollection",
        "features": features
    }

@router.get("/global-map", response_class=HTMLResponse)
def get_global_osint_map(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html)
):
    """Renders the Global Intelligence Map showing all target infrastructure."""
    return templates.TemplateResponse("osint/map.html", {
        "request": request,
        "user": user,
        "target": None  # Indicates global mode
    })

@router.get("/global-geo-json")
def get_global_osint_geo_json(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user)
):
    """
    Extracts all infrastructure points across ALL targets the user has access to.
    """
    # For now, we fetch all if admin, or all for tenant
    if user.role == 'admin':
        records = session.exec(select(OSINTIntelligence)).all()
    else:
        # Filter by tenant targets
        records = session.exec(
            select(OSINTIntelligence)
            .join(Target)
            .where(Target.tenant_id == user.tenant_id)
        ).all()
        
    features = []
    
    for record in records:
        data = record.data_json
        if not data: continue
        
        geo = data.get("geoip") or {}
        lat = geo.get("lat")
        lon = geo.get("lon")
        
        if lat and lon:
            ip = data.get("ip") or "Unknown IP"
            # Since this is global, we need the domain name from the target
            target = session.get(Target, record.target_id)
            domain = target.domain if target else "Unknown Target"
            subdomain = data.get("subdomain") or domain
            
            feature = {
                "type": "Feature",
                "geometry": {
                    "type": "Point",
                    "coordinates": [lon, lat]
                },
                "properties": {
                    "id": record.id,
                    "target_id": record.target_id,
                    "domain": domain,
                    "label": f"{subdomain} ({ip})",
                    "ip": ip,
                    "subdomain": subdomain,
                    "data_type": record.data_type,
                    "severity": record.severity,
                    "city": geo.get("city", "Unknown"),
                    "country": geo.get("country_name", "Unknown"),
                    "timestamp": record.timestamp.isoformat() if record.timestamp else None
                }
            }
            features.append(feature)
            
    return {
        "type": "FeatureCollection",
        "features": features
    }
