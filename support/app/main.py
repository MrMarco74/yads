from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.database import create_db_tables
from app.routers.ingest import router as ingest_router
from app.routers.admin_keys import router as admin_keys_router
from app.routers.ui import router as ui_router


@asynccontextmanager
async def lifespan(app: FastAPI):
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
app.include_router(ui_router)
