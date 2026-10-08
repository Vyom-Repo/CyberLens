# Routes package
from backend.routes.health import router as health_router
from backend.routes.analyze import router as analyze_router
from backend.routes.history import router as history_router
from backend.routes.report import router as report_router

__all__ = [
    "health_router",
    "analyze_router",
    "history_router",
    "report_router",
]
