"""
Terminator Dashboard - FastAPI Backend
Slim assembler: imports routers, adds middleware, mounts static files.
"""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from web.config import STATIC_DIR
from web.routes import sessions, bounty, findings, graph, infrastructure, websockets

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Terminator Dashboard", version="2.0.0")

# ── CORS ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ──
app.include_router(sessions.router)
app.include_router(bounty.router)
app.include_router(findings.router)
app.include_router(graph.router)
app.include_router(infrastructure.router)

# ── WebSockets (mounted directly on app) ──
websockets.register(app)

# ── Static files ──
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

logger.info("Terminator Dashboard v2.0.0 initialized (static_dir=%s)", STATIC_DIR)


# ── Root + Health ──

@app.get("/")
async def index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return JSONResponse({"message": "Terminator Dashboard API", "docs": "/docs"})


@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.0.0"}
