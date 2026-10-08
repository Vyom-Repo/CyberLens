"""Structured JSON Report Generation and Export endpoint."""

from datetime import datetime, timezone
import json
from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from backend.database.session import get_db
from backend.models.db_models import AnalysisRecord

router = APIRouter(prefix="/api", tags=["Reports"])


@router.get("/report/{record_id}")
async def export_report(record_id: int, db: Session = Depends(get_db)):
    """Generate and download a structured JSON investigation report."""
    record = db.query(AnalysisRecord).filter(AnalysisRecord.id == record_id).first()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation record #{record_id} not found.",
        )

    export_payload = {
        "report_metadata": {
            "report_id": record.id,
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "generator": "Cyber Threat Intelligence Dashboard (CTI-SOC)",
        },
        "ioc_assessment": {
            "ioc": record.ioc,
            "ioc_type": record.ioc_type,
            "investigation_timestamp": record.created_at.isoformat(),
            "risk_score": record.risk_score,
            "risk_level": record.risk_level,
            "confidence": record.confidence,
            "executive_summary": record.summary,
        },
        "unified_intelligence": record.raw_report,
    }

    # Format into clean indented JSON
    json_bytes = json.dumps(export_payload, indent=2).encode("utf-8")
    safe_filename = f"cti_report_id_{record.id}_{record.ioc_type.lower()}.json"

    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_filename}"',
            "Cache-Control": "no-cache",
        },
    )
