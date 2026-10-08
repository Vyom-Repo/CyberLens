"""IOC Analysis and Validation REST endpoints."""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.database.session import get_db
from backend.models.db_models import AnalysisRecord
from backend.schemas.normalized import UnifiedIOCReport
from backend.schemas.request import AnalyzeRequest, ValidateRequest
from backend.schemas.response import AnalysisResponse, ValidateResponse
from backend.services.intel.dispatcher import IntelDispatcher
from backend.services.ioc.validator import validate_ioc
from backend.services.normalization.normalizer import normalize_intelligence
from backend.services.risk.engine import RiskEngine

router = APIRouter(prefix="/api", tags=["Analysis"])

# Module-level singletons for efficient query handling
dispatcher = IntelDispatcher()
risk_engine = RiskEngine()


@router.post("/validate", response_model=ValidateResponse)
async def validate_endpoint(payload: ValidateRequest):
    """Fast pre-flight check to validate and categorize an IOC without external calls."""
    result = validate_ioc(payload.ioc)
    return ValidateResponse(
        valid=result.valid,
        sanitized_ioc=result.sanitized_ioc,
        detected_type=result.ioc_type,
        is_routable=result.is_routable,
        supported_sources=result.supported_sources,
        error=result.error,
    )


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_endpoint(payload: AnalyzeRequest, db: Session = Depends(get_db)):
    """Execute end-to-end IOC analysis pipeline.

    Workflow:
    1. Validate & sanitize input
    2. Dispatch concurrent external queries (VT / AbuseIPDB)
    3. Normalize heterogeneous responses into standard schema
    4. Calculate explainable risk score & generate justifications
    5. Save analysis to SQLite database
    6. Return unified analysis report
    """
    # 1. Validation & Hygiene
    validation = validate_ioc(payload.ioc, payload.ioc_type)
    if not validation.valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=validation.error or "Invalid IOC input.",
        )

    sanitized_ioc = validation.sanitized_ioc or payload.ioc
    ioc_type = validation.ioc_type or "Unknown"

    # 2. Parallel Upstream Dispatching
    raw_intel = await dispatcher.dispatch(
        ioc=sanitized_ioc,
        ioc_type=ioc_type,
        supported_sources=validation.supported_sources,
    )

    # 3. Normalization
    sources, completeness = normalize_intelligence(
        ioc=sanitized_ioc,
        ioc_type=ioc_type,
        raw_intel=raw_intel,
    )

    # 4. Explainable Risk Scoring
    risk_assessment = risk_engine.compute_risk(
        ioc=sanitized_ioc,
        ioc_type=ioc_type,
        sources=sources,
        completeness=completeness,
    )

    # Build master unified report
    now_utc = datetime.now(timezone.utc).isoformat()
    unified_report = UnifiedIOCReport(
        ioc=sanitized_ioc,
        ioc_type=ioc_type,
        analysis_timestamp=now_utc,
        data_completeness=completeness,
        sources=sources,
        risk_assessment=risk_assessment,
    )

    summary_text = (
        f"{risk_assessment.level} Risk ({risk_assessment.score}/100) — "
        f"{ioc_type} IOC assessed with {risk_assessment.confidence} confidence."
    )

    # 5. Persistence
    record = AnalysisRecord(
        ioc=sanitized_ioc,
        ioc_type=ioc_type,
        created_at=datetime.now(timezone.utc),
        risk_score=risk_assessment.score,
        risk_level=risk_assessment.level,
        confidence=risk_assessment.confidence,
        summary=summary_text,
        raw_report=unified_report.model_dump(),
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    # 6. Response
    return AnalysisResponse(
        id=record.id,
        ioc=record.ioc,
        ioc_type=record.ioc_type,
        created_at=record.created_at.isoformat(),
        risk_score=record.risk_score,
        risk_level=record.risk_level,
        confidence=record.confidence,
        summary=record.summary,
        report=unified_report,
    )
