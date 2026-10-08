"""Health and operational readiness status endpoints."""

from datetime import datetime, timezone
from fastapi import APIRouter

from backend.core.config import settings

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check():
    """Verify system health, operating mode, and threat provider availability."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": "offline_simulation" if settings.offline_mode else "live_network",
        "providers": {
            "virustotal": "configured" if settings.vt_api_key else "missing_key",
            "abuseipdb": "configured" if settings.abuseipdb_api_key else "missing_key",
        },
    }
