from typing import List, Optional
from pydantic import BaseModel, Field
from backend.schemas.normalized import UnifiedIOCReport, RiskAssessment


class ValidateResponse(BaseModel):
    """Response returned by the /api/validate endpoint."""
    valid: bool
    sanitized_ioc: Optional[str] = None
    detected_type: Optional[str] = None
    is_routable: bool = True
    supported_sources: List[str] = Field(default_factory=list)
    error: Optional[str] = None


class AnalysisResponse(BaseModel):
    """Response returned by the /api/analyze endpoint."""
    id: int
    ioc: str
    ioc_type: str
    created_at: str
    risk_score: int
    risk_level: str
    confidence: str
    summary: str
    report: UnifiedIOCReport


class HistoryItemResponse(BaseModel):
    """Summary item for the investigation history table."""
    id: int
    ioc: str
    ioc_type: str
    created_at: str
    risk_score: int
    risk_level: str
    confidence: str
    summary: Optional[str] = None


class HistoryListResponse(BaseModel):
    """Paginated response for the investigation history list."""
    total: int
    items: List[HistoryItemResponse]
