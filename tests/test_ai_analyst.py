import pytest
from backend.models.scan import ScanModel, ScanConfig, ScanSummary, SeverityBreakdown
from backend.models.finding import FindingModel
from backend.models.evidence import EvidenceModel
from backend.ai.analyst import AISecurityAnalyst
from backend.ai.explainer import ExplainableAIEngine
from backend.ai.remediation import RemediationEngine

@pytest.fixture
def mock_scan_with_finding():
    ev = EvidenceModel(
        baseline_response_length=500,
        test_response_length=900,
        length_diff=400,
        status_code_changed=True,
        baseline_status_code=200,
        test_status_code=500,
        error_signature="MySQL syntax error",
        reproducible=True,
        reproduction_count=3,
        detection_rule="sqli_syntax_error"
    )
    finding = FindingModel(
        finding_id="SQLI-001",
        type="SQL Injection",
        title="SQL Injection in id parameter",
        target="http://example.com/api/products",
        parameter="id",
        method="GET",
        severity="CRITICAL",
        risk_score=9.4,
        cvss=8.8,
        confidence=95.0,
        confidence_factors={"evidence": 98.0, "behavior": 85.0, "reproducibility": 100.0, "detector_reliability": 95.0},
        validation_status="Confirmed",
        owasp={"id": "A03:2021", "name": "Injection"},
        cwe={"id": "CWE-89", "name": "SQL Injection"},
        evidence=ev
    )
    summary = ScanSummary(
        total_findings=1,
        severity_breakdown=SeverityBreakdown(critical=1),
        security_score=70.0
    )
    return ScanModel(
        id="SCAN-TEST2",
        target_url="http://example.com",
        profile="standard",
        status="completed",
        config=ScanConfig(target_url="http://example.com"),
        summary=summary,
        findings=[finding]
    )

@pytest.mark.asyncio
async def test_xai_explanation_offline(mock_scan_with_finding):
    finding = mock_scan_with_finding.findings[0]
    explanation = await ExplainableAIEngine.explain(finding)

    assert "why_detected" in explanation
    assert "evidence_factors" in explanation
    assert "confidence_narrative" in explanation
    assert "observed_behavior" in explanation
    assert explanation["evidence_factors"]["reproducibility_score"] == 1.0
    assert "MySQL syntax error" in explanation["why_detected"]

@pytest.mark.asyncio
async def test_remediation_generation(mock_scan_with_finding):
    finding = mock_scan_with_finding.findings[0]
    remediation = await RemediationEngine.generate_remediation(finding)

    assert "problem" in remediation
    assert "recommendation" in remediation
    assert "verification" in remediation
    assert "code_examples" in remediation
    assert "python" in remediation["code_examples"]
    assert "javascript" in remediation["code_examples"]

@pytest.mark.asyncio
async def test_ai_analyst_questions(mock_scan_with_finding):
    finding = mock_scan_with_finding.findings[0]

    # Question 1: Top risks
    res1 = await AISecurityAnalyst.ask("What are the top 3 risks?", mock_scan_with_finding)
    assert len(res1["observed"]) >= 1
    assert len(res1["recommended"]) >= 1

    # Question 2: False positive
    res2 = await AISecurityAnalyst.ask("Could this be a false positive?", mock_scan_with_finding, selected_finding=finding)
    assert "Confirmed" in str(res2["observed"])
    assert "LOW" in str(res2["inferred"])
