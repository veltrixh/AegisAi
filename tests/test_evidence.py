import pytest
from backend.core.evidence import EvidenceCollector
from backend.utils.http_client import ScannerResponse
from backend.utils.sanitizer import sanitize_headers, sanitize_dict_or_str, truncate_snippet

def test_sanitizer_masks_sensitive_tokens():
    raw_headers = {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID",
        "Cookie": "session_id=secret123456789; theme=dark",
        "X-Api-Key": "AIzaSyABC12345678901234567890123456",
        "Content-Type": "application/json"
    }
    sanitized = sanitize_headers(raw_headers)
    assert "[REDACTED]" in sanitized["Authorization"]
    assert "secret123456789" not in sanitized["Cookie"]
    assert "[REDACTED]" in sanitized["Cookie"]
    assert sanitized["X-Api-Key"] == "[REDACTED]"
    assert sanitized["Content-Type"] == "application/json"

def test_sanitizer_dict_recursive():
    payload = {
        "user": "alice",
        "password": "SuperSecretPassword123!",
        "token": "fake-test-token-not-a-real-key"
    }
    cleaned = sanitize_dict_or_str(payload)
    assert cleaned["user"] == "alice"
    assert cleaned["password"] == "[REDACTED]"
    assert cleaned["token"] == "[REDACTED]"

def test_evidence_collector_baseline_diff():
    baseline = ScannerResponse(
        status_code=200,
        headers={"Content-Type": "text/html"},
        text="Normal Product Page",
        elapsed_ms=45.0,
        url="http://test.local/prod?id=1",
        method="GET"
    )
    test_resp = ScannerResponse(
        status_code=500,
        headers={"Content-Type": "text/html"},
        text="Internal Server Error: You have an error in your SQL syntax near...",
        elapsed_ms=62.0,
        url="http://test.local/prod?id=1'",
        method="GET"
    )
    req_data = {
        "method": "GET",
        "url": "http://test.local/prod?id=1'",
        "params": {"id": "1'"}
    }
    evidence = EvidenceCollector.capture(
        baseline=baseline,
        test_response=test_resp,
        test_request_data=req_data,
        error_signature="MySQL Syntax Error",
        detection_rule="sqli_syntax_error",
        payloads_tested=2,
        successful_payloads=1,
        reproducible=True,
        reproduction_count=2
    )

    assert evidence.status_code_changed is True
    assert evidence.baseline_status_code == 200
    assert evidence.test_status_code == 500
    assert evidence.error_signature == "MySQL Syntax Error"
    assert evidence.reproducible is True
    assert evidence.reproduction_count == 2
    assert "Δ" in evidence.diff_summary
