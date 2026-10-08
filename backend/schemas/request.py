from typing import Optional
from pydantic import BaseModel, Field


class ValidateRequest(BaseModel):
    """Payload for IOC pre-validation check."""
    ioc: str = Field(..., min_length=1, max_length=1024, description="The IOC string to validate")


class AnalyzeRequest(BaseModel):
    """Payload for full IOC threat analysis."""
    ioc: str = Field(..., min_length=1, max_length=1024, description="The IOC string to analyze")
    ioc_type: Optional[str] = Field(
        default=None,
        description="Optional explicit IOC type override (e.g. IPv4, Domain, SHA-256)"
    )
