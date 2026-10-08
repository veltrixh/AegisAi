from typing import Optional, Dict, Any, List
from backend.models.evidence import EvidenceModel, RequestEvidence, ResponseEvidence
from backend.utils.http_client import ScannerResponse
from backend.utils.sanitizer import sanitize_headers, sanitize_dict_or_str, truncate_snippet
from backend.utils.logger import logger

class EvidenceCollector:
    """
    Evidence Engine: Collects deterministic, auditable, and sanitized evidence
    by comparing baseline requests against probe requests and verifying reproducibility.
    """

    @staticmethod
    def capture(
        baseline: Optional[ScannerResponse],
        test_response: ScannerResponse,
        test_request_data: Dict[str, Any],
        error_signature: Optional[str] = None,
        detection_rule: str = "heuristic_anomaly",
        payload_category: str = "injection",
        payloads_tested: int = 1,
        successful_payloads: int = 1,
        reproduction_count: int = 1,
        reproducible: bool = True,
        snippet_pattern: Optional[str] = None,
        extra_behavior: Optional[Dict[str, Any]] = None
    ) -> EvidenceModel:
        """
        Builds a comprehensive EvidenceModel with sanitized requests, responses,
        and behavioral comparison against baseline.
        """
        baseline_length = baseline.length if baseline else 0
        test_length = test_response.length
        length_diff = test_length - baseline_length

        baseline_status = baseline.status_code if baseline else 200
        test_status = test_response.status_code
        status_changed = (baseline_status != test_status) if baseline else False

        baseline_time = baseline.elapsed_ms if baseline else 0.0
        test_time = test_response.elapsed_ms
        time_diff = abs(test_time - baseline_time)
        # Significant timing difference (> 2500ms or 3x baseline)
        time_changed = time_diff > 2500 or (baseline_time > 0 and test_time / baseline_time > 3.0)

        # Snippet extraction: locate error signature or pattern if present
        snippet = ""
        if snippet_pattern and snippet_pattern in test_response.text:
            idx = test_response.text.find(snippet_pattern)
            start = max(0, idx - 100)
            end = min(len(test_response.text), idx + len(snippet_pattern) + 200)
            snippet = truncate_snippet(test_response.text[start:end], max_chars=400)
        else:
            snippet = truncate_snippet(test_response.text[:500], max_chars=500)

        # Sanitized request & response
        req_headers = sanitize_headers(test_request_data.get("headers", {}))
        req_params = sanitize_dict_or_str(test_request_data.get("params", {}))
        req_body = sanitize_dict_or_str(test_request_data.get("body", None))
        req_body_str = str(req_body) if req_body is not None else None

        req_evidence = RequestEvidence(
            method=test_request_data.get("method", "GET"),
            url=test_request_data.get("url", test_response.url),
            headers=req_headers,
            body=req_body_str,
            parameters=req_params
        )

        resp_evidence = ResponseEvidence(
            status_code=test_status,
            response_time_ms=round(test_time, 2),
            content_length=test_length,
            snippet=snippet,
            headers=sanitize_headers(test_response.headers)
        )

        behavioral_changes = {
            "status_code_changed": status_changed,
            "response_time_changed": time_changed,
            "length_difference": length_diff,
            "time_difference_ms": round(time_diff, 2),
            "error_signature_detected": bool(error_signature),
            **(extra_behavior or {})
        }

        diff_summary = (
            f"Baseline Status: {baseline_status} vs Test: {test_status} | "
            f"Length: {baseline_length}B -> {test_length}B (Δ {length_diff:+d}B) | "
            f"Latency: {round(baseline_time, 1)}ms -> {round(test_time, 1)}ms"
        )

        return EvidenceModel(
            baseline_response_length=baseline_length,
            test_response_length=test_length,
            length_diff=length_diff,
            status_code_changed=status_changed,
            baseline_status_code=baseline_status,
            test_status_code=test_status,
            response_time_changed=time_changed,
            baseline_time_ms=round(baseline_time, 2),
            test_time_ms=round(test_time, 2),
            error_signature=error_signature,
            payload_category=payload_category,
            payloads_tested=payloads_tested,
            successful_payloads=successful_payloads,
            reproducible=reproducible,
            reproduction_count=reproduction_count,
            detection_rule=detection_rule,
            behavioral_changes=behavioral_changes,
            request=req_evidence,
            response=resp_evidence,
            diff_summary=diff_summary
        )
