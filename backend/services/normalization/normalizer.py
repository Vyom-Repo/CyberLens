"""Data Normalization Layer.

Transforms heterogeneous raw payloads from VirusTotal and AbuseIPDB into
standardized internal Pydantic models (EngineStats, NormalizedVTData,
NormalizedAbuseIPDBData, UnifiedSources).
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from backend.schemas.normalized import (
    EngineStats,
    NormalizedAbuseIPDBData,
    NormalizedVTData,
    UnifiedSources,
)


def _format_timestamp(ts: Optional[int]) -> Optional[str]:
    """Convert Unix epoch timestamp to ISO 8601 UTC string."""
    if not ts:
        return None
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.isoformat()
    except Exception:
        return None


def normalize_virustotal(raw_result: Optional[Dict[str, Any]]) -> NormalizedVTData:
    """Transform raw VirusTotal API v3 response into NormalizedVTData."""
    if not raw_result:
        return NormalizedVTData(status="NOT_QUERIED")

    status = raw_result.get("status", "FAILED")
    data = raw_result.get("data", {}) or {}

    if status == "NOT_FOUND":
        return NormalizedVTData(
            status="NOT_FOUND",
            engine_stats=EngineStats(malicious=0, suspicious=0, harmless=0, undetected=0, total=0),
            detection_ratio=0.0,
            reputation_score=0,
            extra_attributes={"note": "Indicator was not observed or cataloged by VirusTotal."},
        )

    if status != "SUCCESS" or not data:
        return NormalizedVTData(
            status=status,
            extra_attributes={"message": raw_result.get("message", "Query was unsuccessful.")},
        )

    attributes = data.get("attributes", {})
    raw_stats = attributes.get("last_analysis_stats", {})

    malicious = int(raw_stats.get("malicious", 0))
    suspicious = int(raw_stats.get("suspicious", 0))
    harmless = int(raw_stats.get("harmless", 0))
    undetected = int(raw_stats.get("undetected", 0))
    total = malicious + suspicious + harmless + undetected

    detection_ratio = round(malicious / max(1, total), 3) if total > 0 else 0.0
    reputation_score = int(attributes.get("reputation", 0))
    last_analysis_date = _format_timestamp(attributes.get("last_analysis_date"))

    extra = {}
    if "categories" in attributes:
        extra["categories"] = attributes["categories"]
    if "meaningful_name" in attributes:
        extra["filename"] = attributes["meaningful_name"]
    if "type_description" in attributes:
        extra["file_type"] = attributes["type_description"]
    if "as_owner" in attributes:
        extra["asn_owner"] = attributes["as_owner"]
    if "country" in attributes:
        extra["country"] = attributes["country"]

    return NormalizedVTData(
        status="SUCCESS",
        engine_stats=EngineStats(
            malicious=malicious,
            suspicious=suspicious,
            harmless=harmless,
            undetected=undetected,
            total=total,
        ),
        detection_ratio=detection_ratio,
        reputation_score=reputation_score,
        last_analysis_date=last_analysis_date,
        extra_attributes=extra,
    )


def normalize_abuseipdb(raw_result: Optional[Dict[str, Any]]) -> NormalizedAbuseIPDBData:
    """Transform raw AbuseIPDB API v2 response into NormalizedAbuseIPDBData."""
    if not raw_result:
        return NormalizedAbuseIPDBData(status="NOT_QUERIED")

    status = raw_result.get("status", "FAILED")
    data = raw_result.get("data", {}) or {}

    if status == "NOT_FOUND":
        return NormalizedAbuseIPDBData(
            status="NOT_FOUND",
            abuse_confidence_score=0,
            total_reports=0,
            distinct_users=0,
        )

    if status != "SUCCESS" or not data:
        return NormalizedAbuseIPDBData(status=status)

    return NormalizedAbuseIPDBData(
        status="SUCCESS",
        abuse_confidence_score=int(data.get("abuseConfidenceScore", 0)),
        total_reports=int(data.get("totalReports", 0)),
        distinct_users=int(data.get("numDistinctUsers", 0)),
        last_reported_at=data.get("lastReportedAt"),
        country_code=data.get("countryCode"),
        usage_type=data.get("usageType"),
        isp=data.get("isp"),
        domain=data.get("domain"),
    )


def normalize_intelligence(
    ioc: str,
    ioc_type: str,
    raw_intel: Dict[str, Any],
) -> Tuple[UnifiedSources, str]:
    """Master normalization function.

    Returns:
        Tuple of (UnifiedSources, data_completeness string).
    """
    vt_normalized = normalize_virustotal(raw_intel.get("virustotal"))
    abuse_normalized = (
        normalize_abuseipdb(raw_intel.get("abuseipdb"))
        if "abuseipdb" in raw_intel and raw_intel["abuseipdb"] is not None
        else None
    )

    sources = UnifiedSources(
        virustotal=vt_normalized,
        abuseipdb=abuse_normalized,
    )

    # Determine data completeness
    is_ip = ioc_type.upper() in ("IPV4", "IPV6")
    if is_ip:
        vt_ok = vt_normalized.status in ("SUCCESS", "NOT_FOUND")
        abuse_ok = abuse_normalized is not None and abuse_normalized.status in ("SUCCESS", "NOT_FOUND")

        if vt_ok and abuse_ok:
            completeness = "FULL"
        elif vt_ok or abuse_ok:
            completeness = "PARTIAL"
        else:
            completeness = "INSUFFICIENT_DATA"
    else:
        # Single-source indicators (Domain, URL, Hash)
        if vt_normalized.status in ("SUCCESS", "NOT_FOUND"):
            completeness = "FULL"
        else:
            completeness = "INSUFFICIENT_DATA"

    return sources, completeness
