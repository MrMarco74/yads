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
        if os.path.exists(f"/app/{guide_path}"):
            guide_path = f"/app/{guide_path}"
        else:
            return HTMLResponse(" User Guide not found.", status_code=404)
            
    async with aiofiles.open(guide_path, mode='r') as f:
        content = await f.read()
        
    # Convert Markdown to HTML
    html_content = markdown.markdown(
        content, 
        extensions=['fenced_code', 'tables', 'toc']
    )
    
    return templates.TemplateResponse("help.html", {
        "request": request,
        "content": html_content,
        "user": user
    })
