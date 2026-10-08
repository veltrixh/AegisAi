from typing import Dict, Any, List
from backend.models.finding import FindingModel
from backend.intelligence.cvss import score_to_severity

class RiskEngine:
    """
    Deterministic risk calculation engine independent of LLMs.
    Calculates finding risk score (0.0 to 10.0), severity tier,
    and overall global Security Posture Score (0 to 100).
    """

    @classmethod
    def calculate_finding_risk(
        cls,
        cvss_score: float,
        confidence: float,
        asset_criticality: float = 1.0,     # 0.5 (low value asset) to 1.5 (high value)
        exposure_factor: float = 1.0,       # 1.0 internet-facing, 0.7 internal
        attack_complexity: str = "L"         # "L" low complexity (easier to exploit), "H" high
    ) -> float:
        """
        Computes composite finding risk score normalized to 0.0 - 10.0.
        Equation combines CVSS with exploitability factors, asset value, and detection confidence.
        """
        # Exploitability boost: Low attack complexity increases risk
        ac_modifier = 1.1 if attack_complexity.upper() == "L" else 0.9

        # Confidence weight: Lower confidence slightly attenuates risk to avoid panicking on false positives
        conf_weight = 0.5 + (confidence / 200.0)  # 0.5 to 1.0

        raw_risk = cvss_score * ac_modifier * exposure_factor * asset_criticality * conf_weight
        clamped = max(0.0, min(10.0, raw_risk))
        return round(clamped, 1)

    @classmethod
    def calculate_security_posture(
        cls,
        findings: List[FindingModel],
        total_endpoints: int = 1
    ) -> Dict[str, Any]:
        """
        Computes the global Security Posture Score (0 - 100) and severity breakdown.
        Starts at 100 and applies weighted penalties based on verified severity & confidence.
        """
        crit_count = 0
        high_count = 0
        med_count = 0
        low_count = 0
        info_count = 0

        total_penalty = 0.0

        for f in findings:
            sev = f.severity.upper()
            conf_multiplier = f.confidence / 100.0

            if sev == "CRITICAL":
                crit_count += 1
                total_penalty += 25.0 * conf_multiplier
            elif sev == "HIGH":
                high_count += 1
                total_penalty += 15.0 * conf_multiplier
            elif sev == "MEDIUM":
                med_count += 1
                total_penalty += 6.0 * conf_multiplier
            elif sev == "LOW":
                low_count += 1
                total_penalty += 2.0 * conf_multiplier
            else:
                info_count += 1
                total_penalty += 0.5 * conf_multiplier

        # Additional small penalty for broad attack surface
        surface_penalty = min(5.0, total_endpoints * 0.2)
        total_penalty += surface_penalty

        posture_score = max(0.0, min(100.0, 100.0 - total_penalty))
        posture_score = round(posture_score, 1)

        # Rating tier
        if posture_score >= 85.0:
            rating = "SECURE / EXCELLENT"
        elif posture_score >= 70.0:
            rating = "ACCEPTABLE / MODERATE RISK"
        elif posture_score >= 50.0:
            rating = "POOR / HIGH RISK"
        else:
            rating = "CRITICAL RISK / IMMEDIATE ACTION REQUIRED"

        return {
            "score": posture_score,
            "rating": rating,
            "counts": {
                "critical": crit_count,
                "high": high_count,
                "medium": med_count,
                "low": low_count,
                "informational": info_count
            }
        }
