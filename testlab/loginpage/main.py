"""
Login Surface Test Target — for login_scanner and password_spray_mapper.
Exposes multiple login endpoints without rate limiting or lockout.
"""
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="TestLab Login Surface")
templates = Jinja2Templates(directory="templates")

USERS = {"admin": "admin123", "user": "password1", "test": "test"}

def _check(username, password):
    return USERS.get(username) == password


# ── Enumerable login endpoints (password spray surface) ──────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
@app.post("/login", response_class=HTMLResponse)
async def login(request: Request, username: str = Form(default=""), password: str = Form(default="")):
    if request.method == "POST":
        ok = _check(username, password)
        return templates.TemplateResponse("login.html", {"request": request, "success": ok, "error": not ok})
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/admin", response_class=HTMLResponse)
@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login(request: Request):
    return templates.TemplateResponse("admin.html", {"request": request})

@app.post("/admin/login")
async def admin_login_post(username: str = Form(...), password: str = Form(...)):
    return JSONResponse({"success": _check(username, password), "role": "admin" if username == "admin" else "user"})

@app.get("/wp-login.php", response_class=HTMLResponse)
async def wp_login(request: Request):
    return templates.TemplateResponse("wp.html", {"request": request})

@app.post("/wp-login.php")
async def wp_login_post(log: str = Form(...), pwd: str = Form(...)):
    return JSONResponse({"loggedIn": _check(log, pwd)})

@app.get("/api/auth/login")
@app.post("/api/auth/login")
async def api_login(request: Request):
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    u, p = body.get("username", ""), body.get("password", "")
    return JSONResponse({"token": f"fake-jwt-{u}" if _check(u, p) else None, "error": None if _check(u, p) else "Invalid credentials"})

@app.get("/phpmyadmin/", response_class=HTMLResponse)
async def phpmyadmin(request: Request):
    return HTMLResponse("<html><body><h2>phpMyAdmin</h2><form method='post'><input name='pma_username'><input name='pma_password' type='password'><button>Login</button></form></body></html>")

@app.get("/.well-known/security.txt")
async def no_security_txt():
    # Intentionally returns 404 — security.txt scanner finding
    from fastapi import HTTPException
    raise HTTPException(status_code=404, detail="Not found")
