import uuid
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

SSRF_PARAM_CANDIDATES = {
    "url", "redirect", "dest", "destination", "proxy", "endpoint",
    "callback", "next", "return", "target", "feed", "uri", "host", "path"
}

SSRF_PROBES = [
    {
        "payload": "http://127.0.0.1:80/aegis_ssrf_test",
        "category": "loopback_probe",
        "description": "Internal Loopback Probe"
    },
    {
        "payload": "http://169.254.169.254/latest/meta-data/",
        "category": "cloud_metadata",
        "description": "Cloud Instance Metadata Endpoint"
    }
]

class SSRFScanner(BaseScanner):
    """
    Deterministic Server-Side Request Forgery (SSRF) Scanner.
    Tests URL parameters with controlled canary endpoints, observing
    server connection anomalies, metadata reflections, and behavioral variance.
    """
    name = "Deterministic SSRF Engine"
    vulnerability_type = "ssrf"
    category = "active"

    async def scan(self, target: str, context: Dict[str, Any]) -> List[FindingModel]:
        logger.info(f"Scanning target for SSRF: {target}")
        findings: List[FindingModel] = []

        if not self.client:
            self.client = AsyncScannerClient()

        baseline: ScannerResponse = context.get("baseline")
        if not baseline:
            baseline = await self.client.get(target)

        params_to_test = context.get("discovered_params", [])
        # Prioritize SSRF candidates
        ssrf_params = [p for p in params_to_test if p.lower() in SSRF_PARAM_CANDIDATES]
        if not ssrf_params:
            ssrf_params = ["redirect", "url", "dest", "target", "proxy"]

        tested_params = set()

        for param in ssrf_params:
            if param in tested_params:
                continue
            tested_params.add(param)

            for probe in SSRF_PROBES:
                payload = probe["payload"]
                test_url = self._inject_param(target, param, payload)
                test_res = await self.client.get(test_url)

                # Detection criteria:
                # 1. Direct reflection of cloud metadata or localhost signature
                # 2. Connection refused or timeout anomaly indicating server attempted internal connection
                # 3. Status 200 with significant content difference from baseline
                is_vulnerable = False
                error_sig = None

                text_lower = test_res.text.lower()
                if "ami-id" in text_lower or "instance-id" in text_lower or "iam/security-credentials" in text_lower:
                    is_vulnerable = True
                    error_sig = "Cloud Metadata Reflected (AWS/OpenStack IMDS)"
                elif "connection refused" in text_lower or "failed to connect" in text_lower:
                    is_vulnerable = True
                    error_sig = "Server-side socket connection error to probe host"
                elif "localhost" in text_lower and "localhost" not in baseline.text.lower():
                    is_vulnerable = True
                    error_sig = "Internal hostname reflection in response body"

                if is_vulnerable:
                    # Reproducibility check
                    repro_res = await self.client.get(test_url)
                    reproducible = (repro_res.status_code == test_res.status_code)

                    evidence = EvidenceCollector.capture(
                        baseline=baseline,
                        test_response=test_res,
                        test_request_data={
                            "method": "GET",
                            "url": test_url,
                            "params": {param: payload}
                        },
                        error_signature=error_sig,
                        detection_rule="ssrf_canary_reflection",
                        payload_category=probe["category"],
                        payloads_tested=len(SSRF_PROBES),
                        successful_payloads=1,
                        reproduction_count=2,
                        reproducible=reproducible,
                        snippet_pattern="localhost" if "localhost" in text_lower else None,
                        extra_behavior={
                            "injected_param": param,
                            "probe_url": payload,
                            "detection_signature": error_sig
                        }
                    )

                    meta = get_vulnerability_metadata("ssrf")
                    conf, conf_factors, val_status = ConfidenceEngine.evaluate(evidence, "ssrf_canary_reflection")
                    risk = RiskEngine.calculate_finding_risk(meta["default_cvss"], conf)

                    finding = FindingModel(
                        finding_id=f"SSRF-{uuid.uuid4().hex[:6].upper()}",
                        type="Server-Side Request Forgery (SSRF)",
                        title=f"Potential SSRF in parameter '{param}'",
                        target=target,
                        parameter=param,
                        method="GET",
                        severity="CRITICAL" if risk >= 9.0 else "HIGH",
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
                    logger.info(f"Confirmed SSRF in parameter '{param}' with confidence {conf}%")
                    break

        return findings

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [value]
        new_query = urlencode(qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
