"""Explainable Threat Risk Assessment Engine.

Computes deterministic, transparent risk scores (0-100) and classifications
(LOW, MEDIUM, HIGH, CRITICAL) using configurable rules from risk_rules.yaml.
"""

from typing import Any, Dict, List, Optional
from backend.core.rule_loader import load_risk_rules
from backend.schemas.normalized import RiskAssessment, UnifiedSources


class RiskEngine:
    """Calculates explainable risk scores and generates attribution justifications."""

    def __init__(self, rules: Optional[Dict[str, Any]] = None):
        self.rules = rules or load_risk_rules()

    def _calculate_vt_subscore(self, vt_data, ioc_type: str) -> float:
        """Calculate VirusTotal sub-score (0-100)."""
        if not vt_data or vt_data.status != "SUCCESS":
            return 0.0

        stats = vt_data.engine_stats
        malicious = stats.malicious
        suspicious = stats.suspicious
        total = stats.total

        if malicious == 0 and suspicious == 0:
            return 0.0

        # Special calibration for File Hashes (AV consensus)
        if ioc_type.upper() in ("MD5", "SHA-1", "SHA-256"):
            hash_rules = self.rules.get("overrides", {}).get("hash_malicious_thresholds", {})
            if malicious >= hash_rules.get("critical", 5):
                return min(100.0, 80.0 + (malicious * 0.35))
            elif malicious >= hash_rules.get("high", 2):
                return min(74.0, 55.0 + (malicious * 3.0))
            elif malicious >= hash_rules.get("medium", 1):
                return 25.0
            return 0.0

        vt_cfg = self.rules.get("virustotal", {})
        susp_weight = vt_cfg.get("suspicious_weight", 0.5)
        scaling_factor = vt_cfg.get("scaling_factor", 2.5)
        base_thresh = vt_cfg.get("base_penalty_threshold", 3)
        base_penalty = vt_cfg.get("base_penalty_score", 25)

        effective_malicious = malicious + (suspicious * susp_weight)
        effective_total = max(1, total)

        ratio_score = (effective_malicious / effective_total) * 100.0 * scaling_factor
        score = ratio_score

        if malicious >= base_thresh:
            score += base_penalty

        return min(100.0, max(0.0, score))

    def _calculate_abuse_subscore(self, abuse_data) -> float:
        """Calculate AbuseIPDB sub-score (0-100)."""
        if not abuse_data or abuse_data.status != "SUCCESS":
            return 0.0

        abuse_cfg = self.rules.get("abuseipdb", {})
        conf_weight = abuse_cfg.get("confidence_weight", 0.85)
        vol_weight = abuse_cfg.get("report_volume_weight", 0.15)
        vol_mult = abuse_cfg.get("report_multiplier", 2.0)

        confidence = float(abuse_data.abuse_confidence_score)
        total_reports = float(abuse_data.total_reports)

        volume_contrib = min(100.0, total_reports * vol_mult)
        score = (confidence * conf_weight) + (volume_contrib * vol_weight)

        return min(100.0, max(0.0, score))

    def _determine_tier(self, score: int) -> str:
        """Map numerical score to configured risk classification tier."""
        thresholds = self.rules.get("thresholds", {})
        for tier_key, tier_data in thresholds.items():
            if tier_data.get("min", 0) <= score <= tier_data.get("max", 100):
                return tier_data.get("label", tier_key.upper())

        if score >= 75:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 20:
            return "MEDIUM"
        return "LOW"

    def _build_justifications(
        self,
        ioc_type: str,
        sources: UnifiedSources,
        completeness: str,
        final_score: int,
    ) -> List[str]:
        """Generate human-readable, auditable justification statements."""
        justifications: List[str] = []
        vt = sources.virustotal
        abuse = sources.abuseipdb

        # 1. VirusTotal Findings
        if vt and vt.status == "SUCCESS":
            stats = vt.engine_stats
            if stats.malicious > 0:
                engine_str = "security engine" if stats.malicious == 1 else "security engines"
                justifications.append(
                    f"VirusTotal flagged as malicious by {stats.malicious} {engine_str} "
                    f"(detection ratio: {vt.detection_ratio * 100:.1f}% out of {stats.total} scanners)."
                )
                if stats.suspicious > 0:
                    justifications.append(
                        f"An additional {stats.suspicious} engines classified the indicator as suspicious."
                    )
            else:
                justifications.append(
                    f"Zero security vendors on VirusTotal identified this indicator as malicious (0/{stats.total})."
                )

            # Categorical metadata
            cats = vt.extra_attributes.get("categories", {})
            if cats:
                cat_names = list(cats.values())[:2]
                justifications.append(f"Security categories identified: {', '.join(cat_names)}.")
        elif vt and vt.status == "NOT_FOUND":
            justifications.append("Indicator has no prior detection records or history on VirusTotal.")

        # 2. AbuseIPDB Findings
        if abuse and abuse.status == "SUCCESS":
            if abuse.abuse_confidence_score > 0 or abuse.total_reports > 0:
                justifications.append(
                    f"AbuseIPDB confidence score is {abuse.abuse_confidence_score}% with "
                    f"{abuse.total_reports} abuse reports filed across {abuse.distinct_users} distinct reporters."
                )
            else:
                justifications.append("AbuseIPDB has zero recorded abuse reports for this IP address.")

            if abuse.isp:
                justifications.append(f"Associated ISP/Network: {abuse.isp} ({abuse.country_code or 'Unknown'}).")
        elif abuse and abuse.status == "NOT_FOUND":
            justifications.append("IP address has zero recorded abuse reports in AbuseIPDB.")

        # 3. Overall Contextual Summary
        if final_score >= 75:
            justifications.append("Severe risk consensus: Immediate blocking and containment recommended.")
        elif final_score >= 50:
            justifications.append("Elevated risk: Potentially compromised or actively malicious infrastructure.")
        elif final_score >= 20:
            justifications.append("Moderate risk: Minor threat signals present; contextual review advised.")
        elif final_score == 0:
            justifications.append("Clean reputation: No threat indicators identified across active threat feeds.")

        # 4. Partial Availability Warning
        if completeness == "PARTIAL":
            justifications.append("Note: Assessment derived from partial intelligence feeds due to provider availability.")
        elif completeness == "INSUFFICIENT_DATA":
            justifications.append("Warning: Threat feeds returned insufficient data to provide a conclusive score.")

        return justifications

    def compute_risk(
        self,
        ioc: str,
        ioc_type: str,
        sources: UnifiedSources,
        completeness: str = "FULL",
    ) -> RiskAssessment:
        """Master execution: computes score, tier, confidence, and justifications."""
        vt = sources.virustotal
        abuse = sources.abuseipdb

        vt_score = self._calculate_vt_subscore(vt, ioc_type)
        abuse_score = self._calculate_abuse_subscore(abuse)

        weights = self.rules.get("weights", {})
        vt_weight = weights.get("virustotal", 0.55)
        abuse_weight = weights.get("abuseipdb", 0.45)

        # Dual-source vs single-source computation
        vt_valid = vt is not None and vt.status in ("SUCCESS", "NOT_FOUND")
        abuse_valid = abuse is not None and abuse.status in ("SUCCESS", "NOT_FOUND")

        if vt_valid and abuse_valid:
            raw_score = (vt_score * vt_weight) + (abuse_score * abuse_weight)
        elif vt_valid:
            raw_score = vt_score
        elif abuse_valid:
            raw_score = abuse_score
        else:
            raw_score = 0.0

        # Consensus overrides (prevent mathematical dilution)
        overrides = self.rules.get("overrides", {})
        vt_crit_thresh = overrides.get("vt_malicious_critical_threshold", 10)
        abuse_crit_thresh = overrides.get("abuse_confidence_critical_threshold", 90)

        if vt and vt.status == "SUCCESS" and vt.engine_stats.malicious >= vt_crit_thresh:
            raw_score = max(raw_score, 80.0)

        if abuse and abuse.status == "SUCCESS" and abuse.abuse_confidence_score >= abuse_crit_thresh:
            raw_score = max(raw_score, 80.0)

        # If completely clean on all active engines, guaranteed 0
        all_clean = True
        if vt and vt.status == "SUCCESS" and (vt.engine_stats.malicious > 0 or vt.engine_stats.suspicious > 0):
            all_clean = False
        if abuse and abuse.status == "SUCCESS" and (abuse.abuse_confidence_score > 0 or abuse.total_reports > 0):
            all_clean = False

        if all_clean and (vt_valid or abuse_valid):
            final_score = 0
        else:
            final_score = int(round(min(100.0, max(0.0, raw_score))))

        tier = self._determine_tier(final_score)

        # Assessment confidence mapping
        if completeness == "FULL":
            confidence = "HIGH"
        elif completeness == "PARTIAL":
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        justifications = self._build_justifications(ioc_type, sources, completeness, final_score)

        return RiskAssessment(
            score=final_score,
            level=tier,
            confidence=confidence,
            justifications=justifications,
        )
