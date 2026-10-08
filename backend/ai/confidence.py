from typing import Dict, Any, Tuple
from backend.models.evidence import EvidenceModel

class ConfidenceEngine:
    """
    Deterministic confidence calculation and false positive validation engine.
    Calculates weighted confidence 0-100 and classifies validation status:
    Confirmed | Likely | Suspicious | Potential False Positive.
    """

    DETECTOR_RELIABILITY_MAP = {
        "sqli_syntax_error": 0.95,
        "sqli_boolean_diff": 0.90,
        "xss_reflected_exact": 0.95,
        "xss_reflected_attribute": 0.85,
        "csrf_missing_token_state_changing": 0.90,
        "csrf_missing_token_get": 0.60,
        "ssrf_canary_reflection": 0.96,
        "ssrf_timing_anomaly": 0.75,
        "security_headers_passive": 0.99,
        "tls_passive": 0.99,
        "api_unauthenticated_endpoint": 0.92,
        "api_excessive_data_exposure": 0.85,
        "heuristic_anomaly": 0.65
    }

    @classmethod
    def evaluate(
        cls,
        evidence: EvidenceModel,
        rule_name: str,
        detector_base_reliability: float = 0.90
    ) -> Tuple[float, Dict[str, float], str]:
        """
        Computes deterministic confidence score (0-100), factor scores,
        and validation status classification.
        Returns: (confidence, factor_dict, validation_status)
        """
        # 1. Evidence Factor (0 - 100)
        if evidence.error_signature:
            ev_score = 98.0
        elif evidence.response and evidence.response.snippet and ("<script>" in evidence.response.snippet or "alert(" in evidence.response.snippet):
            ev_score = 95.0
        elif evidence.successful_payloads > 0 and evidence.reproducible:
            ev_ratio = evidence.successful_payloads / max(evidence.payloads_tested, 1)
            ev_score = 70.0 + (ev_ratio * 25.0)
        elif evidence.successful_payloads > 0:
            ev_score = 45.0
        else:
            ev_score = 20.0

        # 2. Behavioral Factor (0 - 100)
        beh_score = 30.0
        if evidence.status_code_changed:
            beh_score += 25.0
        if abs(evidence.length_diff) > 200:
            beh_score += 25.0
        if evidence.response_time_changed:
            beh_score += 20.0
        beh_score = min(beh_score, 100.0)

        # 3. Reproducibility Factor (0 - 100)
        if evidence.reproducible and evidence.reproduction_count >= 2:
            rep_score = 100.0
        elif evidence.reproducible and evidence.reproduction_count == 1:
            rep_score = 85.0
        elif evidence.reproducible:
            rep_score = 70.0
        else:
            rep_score = 0.0

        # 4. Detector Reliability Factor (0 - 100)
        rel = cls.DETECTOR_RELIABILITY_MAP.get(rule_name, detector_base_reliability)
        det_score = rel * 100.0

        # Weighted composite score:
        # Evidence: 35%, Behavior: 25%, Reproducibility: 25%, Detector Reliability: 15%
        weighted_conf = (
            (ev_score * 0.35) +
            (beh_score * 0.25) +
            (rep_score * 0.25) +
            (det_score * 0.15)
        )
        final_conf = round(max(0.0, min(100.0, weighted_conf)), 1)

        factors = {
            "evidence": round(ev_score, 1),
            "behavior": round(beh_score, 1),
            "reproducibility": round(rep_score, 1),
            "detector_reliability": round(det_score, 1)
        }

        # Determine validation status
        if final_conf >= 90.0 and evidence.reproducible:
            status = "Confirmed"
        elif final_conf >= 75.0:
            status = "Likely"
        elif final_conf >= 55.0:
            status = "Suspicious"
        else:
            status = "Potential False Positive"

        return final_conf, factors, status
