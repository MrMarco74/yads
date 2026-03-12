from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
import markdown
import os
import aiofiles

from yads.auth.deps import get_current_user_html_optional
from yads.models import User

router = APIRouter(
    prefix="/help",
    tags=["help"]
)

from yads.api.templating import templates

def get_all_tenants():
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import Tenant
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()

templates.env.globals['get_available_tenants'] = get_all_tenants

@router.get("/", response_class=HTMLResponse)
async def view_user_guide(
    request: Request, 
    user: User = Depends(get_current_user_html_optional)
):
    """
    Renders the User Guide from USER_GUIDE.md
    """
    guide_path = "USER_GUIDE.md"
    
    if not os.path.exists(guide_path):
        # Fallback for Docker environment if path differs, or just error
        # Try adjusting path relative to root if needed.
        # Fallback for Docker environment
        if os.path.exists("/app/USER_GUIDE.md"):
            guide_path = "/app/USER_GUIDE.md"
        # Fallback for dev environment (relative to yads/api/routers/../../..)
        elif os.path.exists("../../USER_GUIDE.md"):
             guide_path = "../../USER_GUIDE.md"
        elif os.path.exists("../../../USER_GUIDE.md"):
             guide_path = "../../../USER_GUIDE.md"
        else:
             # Last resort: Try absolute path in typical dev location
             dev_path = "/home/mrmarco/Documents/gitlab/yads/USER_GUIDE.md"
             if os.path.exists(dev_path):
                 guide_path = dev_path
             else:
                return HTMLResponse("<h1>Error: USER_GUIDE.md not found</h1><p>Please insure the file exists in the application root.</p>", status_code=404)
            
    async with aiofiles.open(guide_path, mode='r') as f:
        content = await f.read()
        
    # Convert Markdown to HTML
    html_content = markdown.markdown(
        content, 
        extensions=['fenced_code', 'tables', 'toc']
    )
    
    from yads.config import settings
    

    return templates.TemplateResponse("help.html", {
        "request": request,
        "content": html_content,
        "user": user,
        "settings": settings  # Fix: Pass settings for base.html footer
    })

@router.get("/about", response_class=HTMLResponse)
async def view_about(request: Request, user: User = Depends(get_current_user_html_optional)):
    """About page with credits and acknowledgements."""
    from yads.config import settings
    return templates.TemplateResponse("about.html", {
        "request": request,
        "user": user,
        "settings": settings
    })


@router.get("/roadmap", response_class=HTMLResponse)
async def view_roadmap(request: Request, user: User = Depends(get_current_user_html_optional)):
    """
    Renders the Roadmap page.
    """
    from yads.config import settings
    return templates.TemplateResponse("roadmap.html", {"request": request, "user": user, "settings": settings})

@router.get("/sbom", response_class=HTMLResponse)
async def view_sbom(request: Request, user: User = Depends(get_current_user_html_optional)):
    """
    Renders the Software BOM page.
    """
    import json
    # Try different locations for sbom.json
    possible_paths = ["sbom.json", "/app/sbom.json", "../../sbom.json"]
    sbom_data = None
    
    for p in possible_paths:
        if os.path.exists(p):
            try:
                with open(p, "r") as f:
                    sbom_data = json.load(f)
                break
            except Exception as e:
                import logging
                logging.getLogger(__name__).debug(f"Failed to load sbom: {e}")
                continue
                
    from yads.config import settings
    return templates.TemplateResponse("help/sbom.html", {
        "request": request, 
        "user": user, 
        "settings": settings,
        "sbom": sbom_data
    })

@router.get("/cbom", response_class=HTMLResponse)
async def view_cbom(request: Request, user: User = Depends(get_current_user_html_optional)):
    """
    Renders the Cryptography BOM page.
    """
    import json
    # Try different locations for cbom.json
    possible_paths = ["cbom.json", "/app/cbom.json", "../../cbom.json"]
    cbom_data = None
    
    for p in possible_paths:
        if os.path.exists(p):
            try:
                with open(p, "r") as f:
                    cbom_data = json.load(f)
                break
            except Exception as e:
                import logging
                logging.getLogger(__name__).debug(f"Failed to load cbom: {e}")
                continue
                
    from yads.config import settings
    return templates.TemplateResponse("help/cbom.html", {
        "request": request, 
        "user": user, 
        "settings": settings,
        "cbom": cbom_data
    })

@router.get("/sbom/download", response_class=JSONResponse)
async def download_sbom(request: Request, user: User = Depends(get_current_user_html_optional)):
    """
    Downloads the SBOM in CycloneDX JSON format.
    """
    import json

    
    # Try different locations for sbom.json
    possible_paths = ["sbom.json", "/app/sbom.json", "../../sbom.json"]
    
    for p in possible_paths:
        if os.path.exists(p):
            try:
                with open(p, "r") as f:
                    sbom_data = json.load(f)
                return JSONResponse(
                    content=sbom_data,
                    headers={"Content-Disposition": "attachment; filename=sbom_cyclonedx.json"}
                )
            except Exception as e:
                import logging
                logging.getLogger(__name__).debug(f"Failed to load sbom for download: {e}")
                continue
    
    raise HTTPException(status_code=404, detail="SBOM file not found")

@router.get("/cbom/download", response_class=JSONResponse)
async def download_cbom(request: Request, user: User = Depends(get_current_user_html_optional)):
    """
    Downloads the CBOM in CycloneDX JSON format.
    """
    import json

    
    # Try different locations for cbom.json
    possible_paths = ["cbom.json", "/app/cbom.json", "../../cbom.json"]
    
    for p in possible_paths:
        if os.path.exists(p):
            try:
                with open(p, "r") as f:
                    cbom_data = json.load(f)
                return JSONResponse(
                    content=cbom_data,
                    headers={"Content-Disposition": "attachment; filename=cbom_cyclonedx.json"}
                )
            except Exception as e:
                import logging
                logging.getLogger(__name__).debug(f"Failed to load cbom for download: {e}")
                continue
    
    raise HTTPException(status_code=404, detail="CBOM file not found")
