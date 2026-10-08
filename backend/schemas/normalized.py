from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EngineStats(BaseModel):
    """Normalized AV engine scan verdict counts."""
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total: int = 0


class NormalizedVTData(BaseModel):
    """Normalized threat data from VirusTotal."""
    status: str = Field(default="NOT_QUERIED", description="SUCCESS, NOT_FOUND, FAILED, RATE_LIMITED, NOT_QUERIED")
    engine_stats: EngineStats = Field(default_factory=EngineStats)
    detection_ratio: float = 0.0
    reputation_score: int = 0
    last_analysis_date: Optional[str] = None
    extra_attributes: Dict[str, Any] = Field(default_factory=dict)


class NormalizedAbuseIPDBData(BaseModel):
    """Normalized threat reputation data from AbuseIPDB."""
    status: str = Field(default="NOT_QUERIED", description="SUCCESS, NOT_FOUND, FAILED, RATE_LIMITED, NOT_QUERIED")
    abuse_confidence_score: int = 0
    total_reports: int = 0
    distinct_users: int = 0
    last_reported_at: Optional[str] = None
    country_code: Optional[str] = None
    usage_type: Optional[str] = None
    isp: Optional[str] = None
    domain: Optional[str] = None


class RiskAssessment(BaseModel):
    """Calculated risk assessment with explainable justifications."""
    score: int = Field(..., ge=0, le=100, description="Risk score bounded between 0 and 100")
    level: str = Field(..., description="LOW, MEDIUM, HIGH, CRITICAL")
    confidence: str = Field(default="HIGH", description="HIGH, MEDIUM, LOW")
    justifications: List[str] = Field(default_factory=list, description="Itemized rationale points")


class UnifiedSources(BaseModel):
    """Container for normalized intelligence feeds."""
    virustotal: Optional[NormalizedVTData] = None
    abuseipdb: Optional[NormalizedAbuseIPDBData] = None


class UnifiedIOCReport(BaseModel):
    """Unified internal representation of all intelligence gathered for an IOC."""
    ioc: str
    ioc_type: str
    analysis_timestamp: str
    data_completeness: str = Field(default="FULL", description="FULL, PARTIAL, INSUFFICIENT_DATA")
    sources: UnifiedSources
    risk_assessment: RiskAssessment
