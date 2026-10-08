"""FastAPI application factory and server entry point."""

from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.core.config import settings
from backend.database.session import Base, engine
from backend.routes import (
    analyze_router,
    health_router,
    history_router,
    report_router,
)

# Resolve paths
ROOT_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = ROOT_DIR / "frontend"


# Ensure tables are created immediately
Base.metadata.create_all(bind=engine)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle event handler: ensures database tables are initialized on startup."""
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Cyber Threat Intelligence Dashboard",
    description="SOC Analyst IOC Analysis and Risk Assessment REST API",
    version="1.0.0",
    lifespan=lifespan,
)

# Configure CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(health_router)
app.include_router(analyze_router)
app.include_router(history_router)
app.include_router(report_router)

# Mount Frontend static directory for direct local browser access
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.main:app",
        host=settings.host,
        port=settings.port,
        reload=True,
    )
