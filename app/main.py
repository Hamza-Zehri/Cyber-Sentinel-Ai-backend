"""
Cyber Sentinel AI - Backend Application Entrypoint
"""
import logging

import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.config import settings
from app.database import SessionLocal, init_db
from app.routers import auth as auth_router
from app.routers import network_monitor as network_monitor_router
from app.routers import alerts as alerts_router
from app.routers import ai_security as ai_security_router
from app.routers import admin as admin_router
from app.routers import reports as reports_router
from app.routers import settings as settings_router
from app.routers import notifications as notifications_router
from app.routers import backups as backups_router
from app.routers import credentials as credentials_router
from app.seed import run_all_seeds

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
logger = logging.getLogger("cybersentinel")

limiter = Limiter(key_func=get_remote_address, default_limits=[f"{settings.RATE_LIMIT_PER_MINUTE}/minute"])

app = FastAPI(
    title=settings.APP_NAME,
    description="Enterprise-level AI Cybersecurity Platform — REST API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.CORS_ORIGINS.split(",")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup() -> None:
    logger.info("Starting %s (%s environment)", settings.APP_NAME, settings.APP_ENV)
    init_db()
    db = SessionLocal()
    try:
        run_all_seeds(db)
    finally:
        db.close()
    logger.info("Startup complete. Database ready and seeded.")


@app.get("/api/health", tags=["System"])
def health_check():
    return {"status": "ok", "app": settings.APP_NAME, "environment": settings.APP_ENV}


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s %s", request.method, request.url)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


app.include_router(auth_router.router, prefix=settings.API_V1_PREFIX)
app.include_router(network_monitor_router.router, prefix=settings.API_V1_PREFIX)
app.include_router(alerts_router.router, prefix=settings.API_V1_PREFIX)
app.include_router(ai_security_router.router, prefix=settings.API_V1_PREFIX)
app.include_router(admin_router.router, prefix=settings.API_V1_PREFIX)
app.include_router(reports_router.router, prefix=settings.API_V1_PREFIX)
app.include_router(settings_router.router, prefix=settings.API_V1_PREFIX)
app.include_router(notifications_router.router, prefix=settings.API_V1_PREFIX)
app.include_router(backups_router.router, prefix=settings.API_V1_PREFIX)
app.include_router(credentials_router.router, prefix=settings.API_V1_PREFIX)

# ---- Serve frontend static files (desktop app / local dev) ----
_frontend_dist = settings.FRONTEND_DIST or str(Path(__file__).resolve().parent.parent / "frontend" / "dist")
if os.path.isdir(_frontend_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(_frontend_dist, "assets")), name="assets")
    _index_path = os.path.join(_frontend_dist, "index.html")

    @app.get("/favicon.svg")
    def _favicon():
        return FileResponse(os.path.join(_frontend_dist, "favicon.svg"))

    @app.get("/icons.svg")
    def _icons():
        return FileResponse(os.path.join(_frontend_dist, "icons.svg"))

    @app.get("/{full_path:path}")
    async def _spa(full_path: str):
        if full_path.startswith("api/"):
            return JSONResponse(status_code=404, content={"detail": "Not found"})
        return FileResponse(_index_path)

    logger.info("Serving frontend from %s", _frontend_dist)
