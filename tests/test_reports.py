import pytest
import json
from backend.models.scan import ScanModel, ScanConfig, ScanSummary, SeverityBreakdown
from backend.models.finding import FindingModel
from backend.models.evidence import EvidenceModel
from backend.reports.sarif import SarifExporter
from backend.reports.html import HtmlReportExporter
from backend.reports.pdf import PdfReportExporter

@pytest.fixture
def mock_scan():
    ev = EvidenceModel(
        baseline_response_length=400,
        test_response_length=650,
        status_code_changed=True,
        error_signature="Syntax error",
        reproducible=True,
        reproduction_count=2
    )
    finding = FindingModel(
        finding_id="SQLI-001",
        type="SQL Injection",
        title="SQL Injection in id",
        target="http://example.com/item",
        parameter="id",
        severity="CRITICAL",
        risk_score=9.2,
        cvss=8.8,
        confidence=94.0,
        validation_status="Confirmed",
        owasp={"id": "A03:2021", "name": "Injection"},
        cwe={"id": "CWE-89", "name": "SQL Injection"},
        evidence=ev
    )
    summary = ScanSummary(
        total_findings=1,
        severity_breakdown=SeverityBreakdown(critical=1),
        security_score=75.0
    )
    return ScanModel(
        id="SCAN-TEST1",
        target_url="http://example.com",
        profile="standard",
        status="completed",
        config=ScanConfig(target_url="http://example.com"),
        summary=summary,
        findings=[finding]
    )

def test_sarif_export(mock_scan):
    sarif_data = SarifExporter.export(mock_scan)
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"]) == 1
    run = sarif_data["runs"][0]
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "CWE-89"
    assert run["results"][0]["level"] == "error"

def test_html_report_export(mock_scan):
    html = HtmlReportExporter.render(mock_scan)
    assert "<!DOCTYPE html>" in html
    assert "SQL Injection in id" in html
    assert "75.0" in html
    assert "CWE-89" in html

def test_pdf_report_export(mock_scan):
    pdf_bytes = PdfReportExporter.render_bytes(mock_scan)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")
