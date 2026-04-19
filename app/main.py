"""
Application entry point.

Preferred run command:
    uvicorn app.main:app --reload
"""

from contextlib import asynccontextmanager
from pathlib import Path
import sys

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

if __package__ is None or __package__ == "":
    project_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(project_root))

from app.core.config import settings
from app.core.logging_config import setup_logging
from app.db.database import init_db
from app.routes import auth, report, scan


setup_logging()


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"
PAGE_TEMPLATES = {
    "/": "index.html",
    "/login": "login.html",
    "/register": "register.html",
    "/dashboard": "dashboard.html",
}


# ---------------------------------------------------------------------------
# Application lifespan (startup / shutdown)
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise the database on startup."""
    await init_db()
    yield


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title=settings.app_name,
    description="A minimal security scanning web application.",
    version="1.0.0",
    lifespan=lifespan,
)

# Allow the browser-based frontend to call the API (useful in development)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files (CSS, JS)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Jinja2 templates
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# ---------------------------------------------------------------------------
# Register API routers
# ---------------------------------------------------------------------------

app.include_router(auth.router)
app.include_router(scan.router)
app.include_router(report.router)


# ---------------------------------------------------------------------------
# Frontend page routes (server-side rendered HTML)
# ---------------------------------------------------------------------------


def _render_page(request: Request, template_name: str) -> HTMLResponse:
    return templates.TemplateResponse(template_name, {"request": request})


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index(request: Request):
    """Landing page — redirects unauthenticated users to login."""
    return _render_page(request, PAGE_TEMPLATES["/"])


@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page(request: Request):
    return _render_page(request, PAGE_TEMPLATES["/login"])


@app.get("/register", response_class=HTMLResponse, include_in_schema=False)
async def register_page(request: Request):
    return _render_page(request, PAGE_TEMPLATES["/register"])


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard_page(request: Request):
    return _render_page(request, PAGE_TEMPLATES["/dashboard"])
