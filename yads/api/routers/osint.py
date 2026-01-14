from typing import List, Optional
from fastapi import APIRouter, Depends, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select
import random
import os
import string
from datetime import datetime

from yads.database import get_session
from yads.models import User, Target, Tenant
from yads.auth.deps import get_current_user_html, RoleChecker
from yads.config import settings

# Google API Config (Mock/Stub for now)
GOOGLE_SEARCH_API_KEY = os.getenv("GOOGLE_SEARCH_API_KEY")
GOOGLE_SEARCH_CX = os.getenv("GOOGLE_SEARCH_CX")

router = APIRouter(prefix="/osint", tags=["osint"])
templates = Jinja2Templates(directory="yads/api/templates")

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
def mock_reverse_image_search(filename: str) -> List[str]:
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
        found_domains.append(domain)
    return found_domains

def google_search_stub(filename: str, api_key: str, cx: str) -> List[str]:
    """
    STUB: Real Google Custom Search API implementation (Option 1).
    Currently does NOT execute actual HTTP requests to save costs/quota.
    """
    print(f"GOOGLE_STUB: Would search for image {filename} using Key={api_key[:5]}... CX={cx}")
    
    # In real implementation:
    # url = "https://customsearch.googleapis.com/customsearch/v1"
    # params = {
    #    "key": api_key,
    #    "cx": cx,
    #    "q": f"site related to {filename}", # Simplified, real reverse image search is harder via CSE
    #    "searchType": "image"
    # }
    # resp = requests.get(url, params=params)
    # ... parse items ...
    
    # For now, fallback to mock to show results in UI
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
            
    return templates.TemplateResponse("osint.html", {
        "request": request,
        "user": user,
        "active_tab": "osint"
    })

@router.post("/search", response_class=HTMLResponse)
async def osint_search(
    request: Request,
    files: List[UploadFile] = File(default=[]), # Default to empty list to handle 422
    test_domain: Optional[str] = Form(None), 
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))
):
    print(f"DEBUG: OSINT Search Request. Files: {len(files)}, TestDomain: {test_domain}")
    
    # Validation: Ensure at least one file or test domain
    has_files = False
    for f in files:
        if f.filename:
            has_files = True
            break
            
    if not has_files and not test_domain:
        return "<div class='text-red-400 p-4 border border-red-800 rounded bg-red-900/20'>Please upload an image or provide a test domain.</div>"

    all_found_domains = set()
    
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
        
        print(f"DEBUG: OSINT Using Key: {'(Tenant)' if tenant.google_api_key else '(System)'}")

        # Increment for this batch
        tenant.osint_quota_used += 1
        session.add(tenant)
        session.commit()
    
    # Process uploads
    for file in files:
        if file.filename:
            print(f"DEBUG: Processing file {file.filename}")
            
            # Use Stub if configured, else Mock
            # Pass the determining configuration
            results = google_search_stub(file.filename, api_key, cx)
            
            all_found_domains.update(results)
            
    # Add test domain if provided
    if test_domain and test_domain.strip():
        all_found_domains.add(test_domain.strip().lower())
        
    # Filter against known targets
    # Get all known domains for this tenant
    known_targets = session.exec(select(Target.domain).where(Target.tenant_id == user.tenant_id)).all()
    known_set = set(known_targets)
    
    unknown_domains = []
    already_known = []
    
    for domain in all_found_domains:
        if domain in known_set:
            already_known.append(domain)
        else:
            unknown_domains.append(domain)
            
    return templates.TemplateResponse("_osint_results.html", {
        "request": request,
        "user": user,
        "unknown_domains": sorted(unknown_domains),
        "already_known": sorted(already_known),
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
