import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.models.db import init_db
from backend.api.routes_scan import router as scan_router
from backend.api.routes_findings import router as findings_router
from backend.api.routes_reports import router as reports_router
from backend.api.routes_ai import router as ai_router
from backend.utils.logger import logger

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing database schema...")
    init_db()
    logger.info("AEGIS AI-Vuln-Scanner API initialized successfully.")
    yield

app = FastAPI(
    title="AEGIS AI-Vuln-Scanner Platform",
    description="Evidence-Grounded, Explainable AI Web & API Vulnerability Assessment Platform",
    version="2.0.0",
    lifespan=lifespan
)

# Enable CORS for local dev servers and frontend consoles
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(scan_router)
app.include_router(findings_router)
app.include_router(reports_router)
app.include_router(ai_router)

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "engine": "AEGIS AI-Vuln-Scanner v2.0",
        "ai_status": "active (evidence-grounded)"
    }

# Mount frontend if build exists
frontend_dist = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
if os.path.exists(frontend_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist, "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        file_path = os.path.join(frontend_dist, full_path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(frontend_dist, "index.html"))
