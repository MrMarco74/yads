import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.database import create_db_tables
from app.routers.ingest import router as ingest_router
from app.routers.admin_keys import router as admin_keys_router
from app.routers.installations import router as installations_router
import app.routers.installations as _inst_mod
from app.routers.messages import router as messages_router
from app.routers.ui import router as ui_router
from app.routers.contact import router as contact_router
from app.routers.self_register import router as self_register_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    _inst_mod.ADMIN_TOKEN = os.environ.get("SUPPORT_ADMIN_TOKEN", "")
    create_db_tables()
    yield


app = FastAPI(
    title="YADS Support Portal",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)

app.include_router(ingest_router)
app.include_router(admin_keys_router)
app.include_router(installations_router)
app.include_router(messages_router)
app.include_router(ui_router)
app.include_router(contact_router)
app.include_router(self_register_router)
