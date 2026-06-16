from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from contextlib import asynccontextmanager
import logging
from app.api import cve
from app.core.database import init_db
from app.api import scans, reports, dashboard, auth
from app.api import scheduled_scans
from app.core.config import settings
from app.services.scheduler_service import (
    start_scheduler, stop_scheduler, load_all_scheduled_scans
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting NetScan API...")
    await init_db()

    # Start scheduler and load existing scheduled scans
    start_scheduler()
    await load_all_scheduled_scans()
    logger.info("Scheduler started and jobs loaded")

    yield

    # Shutdown
    stop_scheduler()
    logger.info("Shutting down NetScan API...")


app = FastAPI(
    title="NetScan AI - Network Security Scanner",
    description="AI-powered network port scanner with risk analysis",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(cve.router, prefix="/api/v1/cve", tags=["CVE Lookup"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["Scans"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["Dashboard"])
app.include_router(
    scheduled_scans.router,
    prefix="/api/v1/scheduled-scans",
    tags=["Scheduled Scans"]
)


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "NetScan AI v2.0"}