from pathlib import Path
from typing import Any, Dict
import yaml

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "risk_rules.yaml"


def load_risk_rules(config_path: Path = DEFAULT_CONFIG_PATH) -> Dict[str, Any]:
    """Load and parse the risk scoring rules YAML configuration file."""
    if not config_path.exists():
        # Fallback to sensible defaults if YAML file is missing
        return {
            "thresholds": {
                "low": {"min": 0, "max": 19, "label": "LOW"},
                "medium": {"min": 20, "max": 49, "label": "MEDIUM"},
                "high": {"min": 50, "max": 74, "label": "HIGH"},
                "critical": {"min": 75, "max": 100, "label": "CRITICAL"},
            },
            "weights": {
                "virustotal": 0.55,
                "abuseipdb": 0.45,
            },
            "virustotal": {
                "suspicious_weight": 0.5,
                "scaling_factor": 2.5,
                "base_penalty_threshold": 3,
                "base_penalty_score": 25,
            },
            "abuseipdb": {
                "confidence_weight": 0.85,
                "report_volume_weight": 0.15,
                "report_multiplier": 2.0,
            },
            "overrides": {
                "vt_malicious_critical_threshold": 10,
                "abuse_confidence_critical_threshold": 90,
                "hash_malicious_thresholds": {
                    "critical": 5,
                    "high": 2,
                    "medium": 1,
                },
            },
        }

    with open(config_path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)
