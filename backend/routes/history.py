"""Investigation History REST endpoints."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc
from sqlalchemy.orm import Session

from backend.database.session import get_db
from backend.models.db_models import AnalysisRecord
from backend.schemas.response import (
    AnalysisResponse,
    HistoryItemResponse,
    HistoryListResponse,
)

router = APIRouter(prefix="/api", tags=["History"])


@router.get("/history", response_model=HistoryListResponse)
async def get_history(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    search: Optional[str] = Query(default=None),
    risk_level: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    """Retrieve paginated investigation history with optional search and risk tier filtering."""
    query = db.query(AnalysisRecord)

    if search:
        query = query.filter(AnalysisRecord.ioc.contains(search.strip()))

    if risk_level:
        query = query.filter(AnalysisRecord.risk_level == risk_level.strip().upper())

    total = query.count()
    records = query.order_by(desc(AnalysisRecord.created_at)).offset(offset).limit(limit).all()

    items = [
        HistoryItemResponse(
            id=r.id,
            ioc=r.ioc,
            ioc_type=r.ioc_type,
            created_at=r.created_at.isoformat(),
            risk_score=r.risk_score,
            risk_level=r.risk_level,
            confidence=r.confidence,
            summary=r.summary,
        )
        for r in records
    ]

    return HistoryListResponse(total=total, items=items)


@router.get("/history/{record_id}", response_model=AnalysisResponse)
async def get_history_by_id(record_id: int, db: Session = Depends(get_db)):
    """Retrieve full analysis report for a specific historical investigation."""
    record = db.query(AnalysisRecord).filter(AnalysisRecord.id == record_id).first()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation record #{record_id} not found.",
        )

    return AnalysisResponse(
        id=record.id,
        ioc=record.ioc,
        ioc_type=record.ioc_type,
        created_at=record.created_at.isoformat(),
        risk_score=record.risk_score,
        risk_level=record.risk_level,
        confidence=record.confidence,
        summary=record.summary,
        report=record.raw_report,
    )
