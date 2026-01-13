from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import markdown
import os
import aiofiles

from yads.auth.deps import get_current_user_html_optional
from yads.models import User

router = APIRouter(
    prefix="/help",
    tags=["help"]
)

templates = Jinja2Templates(directory="yads/api/templates")

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

@router.get("/roadmap", response_class=HTMLResponse)
async def view_roadmap(request: Request, user: User = Depends(get_current_user_html_optional)):
    """
    Renders the Roadmap page.
    """
    from yads.config import settings
    return templates.TemplateResponse("roadmap.html", {"request": request, "user": user, "settings": settings})
