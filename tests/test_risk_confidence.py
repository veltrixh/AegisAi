import pytest
from backend.models.evidence import EvidenceModel, ResponseEvidence
from backend.ai.confidence import ConfidenceEngine
from backend.core.risk_engine import RiskEngine
from backend.intelligence.cvss import calculate_cvss_v3, score_to_severity
from backend.models.finding import FindingModel

def test_cvss_v3_calculation():
    # Critical CVSS: SQL Injection standard metrics
    score, vector = calculate_cvss_v3(av="N", ac="L", pr="N", ui="N", scope="U", c="H", i="H", a="H")
    assert score >= 8.5
    assert "CVSS:3.1/AV:N" in vector
    assert score_to_severity(score) in ("HIGH", "CRITICAL")

def test_confidence_engine_confirmed():
    ev = EvidenceModel(
        baseline_response_length=500,
        test_response_length=800,
        length_diff=300,
        status_code_changed=True,
        error_signature="MySQL Syntax Error",
        reproducible=True,
        reproduction_count=3,
        detection_rule="sqli_syntax_error"
    )
    conf, factors, status = ConfidenceEngine.evaluate(ev, "sqli_syntax_error")
    assert conf >= 85.0
    assert factors["reproducibility"] == 100.0
    assert status == "Confirmed"

def test_confidence_engine_potential_false_positive():
    ev = EvidenceModel(
        baseline_response_length=500,
        test_response_length=502,
        length_diff=2,
        status_code_changed=False,
        error_signature=None,
        reproducible=False,
        reproduction_count=0,
        detection_rule="heuristic_anomaly"
    )
    conf, factors, status = ConfidenceEngine.evaluate(ev, "heuristic_anomaly")
    assert conf < 55.0
    assert status == "Potential False Positive"

def test_security_posture_calculation():
    ev = EvidenceModel(status_code_changed=False, reproducible=True)
    f_crit = FindingModel(
        finding_id="F-1", type="SQLi", title="SQLi", target="http://t",
        severity="CRITICAL", risk_score=9.5, cvss=9.0, confidence=95.0,
        evidence=ev
    )
    f_high = FindingModel(
        finding_id="F-2", type="XSS", title="XSS", target="http://t",
        severity="HIGH", risk_score=7.5, cvss=7.2, confidence=90.0,
        evidence=ev
    )
    posture = RiskEngine.calculate_security_posture([f_crit, f_high], total_endpoints=2)
    assert posture["score"] < 75.0
    assert posture["counts"]["critical"] == 1
    assert posture["counts"]["high"] == 1
