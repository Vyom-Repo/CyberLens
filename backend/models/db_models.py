"""SQLAlchemy ORM models for CTI analysis history."""

from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Integer, JSON, String, Text

from backend.database.session import Base


class AnalysisRecord(Base):
    """Database record persisting an individual IOC investigation."""

    __tablename__ = "analysis_records"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ioc = Column(String(512), index=True, nullable=False)
    ioc_type = Column(String(32), nullable=False)
    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(16), nullable=False)
    confidence = Column(String(16), nullable=False)
    summary = Column(Text, nullable=True)
    raw_report = Column(JSON, nullable=False)
