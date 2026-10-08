import uuid
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from backend.scanners.base import BaseScanner
from backend.models.finding import FindingModel
from backend.core.evidence import EvidenceCollector
from backend.ai.confidence import ConfidenceEngine
from backend.core.risk_engine import RiskEngine
from backend.intelligence.knowledge import get_vulnerability_metadata
from backend.utils.http_client import ScannerResponse, AsyncScannerClient
from backend.utils.logger import logger

XSS_PROBES = [
    {"payload": "<script>alert('xss')</script>", "type": "script_tag", "signature": "<script>alert('xss')</script>"},
    {"payload": "\"><script>alert(1)</script>", "type": "attribute_breakout", "signature": "<script>alert(1)</script>"},
    {"payload": "<img src=x onerror=alert(1)>", "type": "event_handler", "signature": "<img src=x onerror=alert(1)>"},
    {"payload": "javascript:alert(1)", "type": "pseudo_protocol", "signature": "javascript:alert(1)"}
]

class XSSScanner(BaseScanner):
    """
    Deterministic Reflected Cross-Site Scripting (XSS) Scanner.
    Injects controlled probe vectors, analyzes unescaped HTML reflection,
    verifies context, and tests reproducibility across multiple requests.
    """
    name = "Deterministic XSS Engine"
    vulnerability_type = "xss_reflected"
    category = "active"

    async def scan(self, target: str, context: Dict[str, Any]) -> List[FindingModel]:
        logger.info(f"Scanning target for Cross-Site Scripting: {target}")
        findings: List[FindingModel] = []

        if not self.client:
            self.client = AsyncScannerClient()

        baseline: ScannerResponse = context.get("baseline")
        if not baseline:
            baseline = await self.client.get(target)

        params_to_test = context.get("discovered_params", [])
        if not params_to_test:
            params_to_test = ["q", "search", "query", "name", "input", "keyword", "comment"]

        tested_params = set()

        for param in params_to_test:
            if param in tested_params:
                continue
            tested_params.add(param)

            matched_signature = None
            successful_payloads = 0
            best_test_response: Optional[ScannerResponse] = None
            best_payload_used = ""
            rule_matched = "xss_reflected_exact"

            for probe in XSS_PROBES:
                payload = probe["payload"]
                signature = probe["signature"]
                test_url = self._inject_param(target, param, payload)
                test_res = await self.client.get(test_url)

                # Check if unescaped signature is present in the response
                if signature in test_res.text:
                    # Verify it's not simply an encoded version like &lt;script&gt;
                    if signature in test_res.text and not f"&lt;script&gt;" in test_res.text:
                        matched_signature = f"Unsanitized reflected payload: {signature}"
                        successful_payloads += 1
                        best_test_response = test_res
                        best_payload_used = payload
                        rule_matched = "xss_reflected_exact"
                        break
                elif "<img src=x" in test_res.text and "onerror" in test_res.text:
                    matched_signature = "Unsanitized HTML tag reflection: <img src=x onerror=...>"
                    successful_payloads += 1
                    best_test_response = test_res
                    best_payload_used = payload
                    rule_matched = "xss_reflected_attribute"
                    break

            if successful_payloads > 0 and best_test_response:
                # Validate reproducibility
                repro_count = 0
                for _ in range(2):
                    repro_url = self._inject_param(target, param, best_payload_used)
                    repro_res = await self.client.get(repro_url)
                    if best_payload_used in repro_res.text:
                        repro_count += 1

                reproducible = repro_count >= 1

                evidence = EvidenceCollector.capture(
                    baseline=baseline,
                    test_response=best_test_response,
                    test_request_data={
                        "method": "GET",
                        "url": self._inject_param(target, param, best_payload_used),
                        "params": {param: best_payload_used}
                    },
                    error_signature=matched_signature,
                    detection_rule=rule_matched,
                    payload_category="xss_reflected",
                    payloads_tested=len(XSS_PROBES),
                    successful_payloads=successful_payloads,
                    reproduction_count=repro_count + 1,
                    reproducible=reproducible,
                    snippet_pattern=best_payload_used,
                    extra_behavior={
                        "reflected_in_body": True,
                        "parameter": param,
                        "raw_payload": best_payload_used
                    }
                )

                meta = get_vulnerability_metadata("xss_reflected")
                conf, conf_factors, val_status = ConfidenceEngine.evaluate(evidence, rule_matched)
                risk = RiskEngine.calculate_finding_risk(meta["default_cvss"], conf)

                finding = FindingModel(
                    finding_id=f"XSS-{uuid.uuid4().hex[:6].upper()}",
                    type="Cross-Site Scripting (Reflected)",
                    title=f"Reflected XSS in parameter '{param}'",
                    target=target,
                    parameter=param,
                    method="GET",
                    severity="HIGH" if risk >= 7.0 else "MEDIUM",
                    risk_score=risk,
                    cvss=meta["default_cvss"],
                    cvss_vector=meta["default_vector"],
                    confidence=conf,
                    confidence_factors=conf_factors,
                    validation_status=val_status,
                    owasp={"id": meta["owasp_id"], "name": meta["owasp_name"]},
                    cwe={"id": meta["cwe_id"], "name": meta["cwe_name"]},
                    evidence=evidence
                )
                findings.append(finding)
                logger.info(f"Confirmed Reflected XSS in '{param}' with confidence {conf}% (status: {val_status})")

        return findings

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [value]
        new_query = urlencode(qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
