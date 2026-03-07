from typing import List, Optional
from fastapi import APIRouter, Depends, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select
import random
import os
import string
from datetime import datetime
import logging

# Setup Logger
logger = logging.getLogger("yads-api")

from yads.database import get_session
from yads.models import User, Target, Tenant
from yads.auth.deps import get_current_user_html, RoleChecker
from yads.config import settings
from yads.utils.license_deps import require_feature

# Google API Config (Mock/Stub for now)
GOOGLE_SEARCH_API_KEY = os.getenv("GOOGLE_SEARCH_API_KEY")
GOOGLE_SEARCH_CX = os.getenv("GOOGLE_SEARCH_CX")

router = APIRouter(prefix="/osint", tags=["osint"], dependencies=[Depends(require_feature("osint"))])
from yads.api.templating import templates

# Inject Globals (Required for base.html)
templates.env.globals['settings'] = settings
templates.env.globals['now_utc'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

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
