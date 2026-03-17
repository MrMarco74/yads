import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.auth import COOKIE_NAME, init_secret, verify_session_token
from app.database import create_db_tables
from app.routers.ingest import router as ingest_router
from app.routers.admin_keys import router as admin_keys_router
from app.routers.installations import router as installations_router
import app.routers.installations as _inst_mod
from app.routers.messages import router as messages_router
from app.routers.ui import router as ui_router
from app.routers.contact import router as contact_router
from app.routers.self_register import router as self_register_router
from app.routers.registry import router as registry_router
from app.routers.categories import router as categories_router

# Paths that don't require a session cookie
_PUBLIC_PREFIXES = ("/login", "/api/", "/static/")


class SessionAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if any(path.startswith(p) for p in _PUBLIC_PREFIXES):
            return await call_next(request)
        token = request.cookies.get(COOKIE_NAME, "")
        if not verify_session_token(token):
            return RedirectResponse(f"/login?next={path}", status_code=303)
        return await call_next(request)


@asynccontextmanager
async def lifespan(app: FastAPI):
    token = os.environ.get("ADMIN_TOKEN", "")
    _inst_mod.ADMIN_TOKEN = token
    init_secret(token)
    create_db_tables()
    yield


app = FastAPI(
    title="YADS Support Portal",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)

app.add_middleware(SessionAuthMiddleware)

app.include_router(ingest_router)
app.include_router(admin_keys_router)
app.include_router(installations_router)
app.include_router(messages_router)
app.include_router(ui_router)
app.include_router(contact_router)
app.include_router(self_register_router)
app.include_router(registry_router)
app.include_router(categories_router)
