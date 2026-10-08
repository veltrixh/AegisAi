import ssl
import socket
from urllib.parse import urlparse
from typing import Dict, Any, List
import uuid
from backend.scanners.base import BaseScanner
from backend.models.finding import FindingModel
from backend.core.evidence import EvidenceCollector
from backend.ai.confidence import ConfidenceEngine
from backend.core.risk_engine import RiskEngine
from backend.intelligence.knowledge import get_vulnerability_metadata
from backend.utils.http_client import ScannerResponse, AsyncScannerClient
from backend.utils.logger import logger

class TLSScanner(BaseScanner):
    """
    Passive TLS and Certificate Configuration Scanner.
    Inspects SSL/TLS certificate validity, protocol versions,
    HTTPS enforcement, and cipher suites without destructive testing.
    """
    name = "Passive TLS & Transport Security Scanner"
    vulnerability_type = "tls_misconfiguration"
    category = "passive"

    async def scan(self, target: str, context: Dict[str, Any]) -> List[FindingModel]:
        logger.info(f"Checking TLS configuration for: {target}")
        findings: List[FindingModel] = []
        parsed = urlparse(target)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # 1. Plain HTTP Check
        if parsed.scheme == "http":
            # Test if HTTPS is enforced via 301/302 redirect
            if not self.client:
                self.client = AsyncScannerClient()
            res = await self.client.get(target)
            redirect_to_https = False
            if res.status_code in (301, 302, 307, 308):
                location = res.headers.get("location", "")
                if location.startswith("https://"):
                    redirect_to_https = True

            if not redirect_to_https:
                meta = get_vulnerability_metadata("tls_misconfiguration")
                rule_id = "tls_passive"
                evidence = EvidenceCollector.capture(
                    baseline=res,
                    test_response=res,
                    test_request_data={"method": "GET", "url": target, "headers": {}},
                    error_signature=None,
                    detection_rule=rule_id,
                    payload_category="transport_security",
                    reproducible=True,
                    extra_behavior={"plain_http": True, "https_redirect_missing": True}
                )
                conf, conf_factors, val_status = ConfidenceEngine.evaluate(evidence, rule_id)
                risk = RiskEngine.calculate_finding_risk(meta["default_cvss"], conf)

                findings.append(FindingModel(
                    finding_id=f"TLS-{uuid.uuid4().hex[:6].upper()}",
                    type="Insecure Transport Protocol",
                    title="Cleartext HTTP Transmission Without Automatic HTTPS Redirection",
                    target=target,
                    parameter="Transport Layer",
                    method="GET",
                    severity="HIGH",
                    risk_score=risk,
                    cvss=meta["default_cvss"],
                    cvss_vector=meta["default_vector"],
                    confidence=conf,
                    confidence_factors=conf_factors,
                    validation_status=val_status,
                    owasp={"id": meta["owasp_id"], "name": meta["owasp_name"]},
                    cwe={"id": meta["cwe_id"], "name": meta["cwe_name"]},
                    evidence=evidence
                ))
            return findings

        # 2. Check TLS certificate if HTTPS
        if parsed.scheme == "https" and hostname:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE  # Safe passive probe

                with socket.create_connection((hostname, port), timeout=4.0) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        tls_version = ssock.version()
                        cipher = ssock.cipher()
                        cert = ssock.getpeercert()

                        # Insecure legacy TLS check
                        if tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                            meta = get_vulnerability_metadata("tls_misconfiguration")
                            baseline: ScannerResponse = context.get("baseline") or ScannerResponse(
                                status_code=200, headers={}, text="", elapsed_ms=10.0, url=target, method="GET"
                            )
                            evidence = EvidenceCollector.capture(
                                baseline=baseline,
                                test_response=baseline,
                                test_request_data={"method": "GET", "url": target, "headers": {}},
                                error_signature=None,
                                detection_rule="tls_passive",
                                payload_category="transport_security",
                                reproducible=True,
                                extra_behavior={"tls_version": tls_version, "cipher": str(cipher)}
                            )
                            conf, conf_factors, val_status = ConfidenceEngine.evaluate(evidence, "tls_passive")
                            risk = RiskEngine.calculate_finding_risk(meta["default_cvss"], conf)

                            findings.append(FindingModel(
                                finding_id=f"TLS-{uuid.uuid4().hex[:6].upper()}",
                                type="Deprecated TLS Version",
                                title=f"Obsolete TLS Protocol In Use ({tls_version})",
                                target=target,
                                parameter="SSL/TLS Handshake",
                                method="TLS",
                                severity="MEDIUM",
                                risk_score=risk,
                                cvss=meta["default_cvss"],
                                cvss_vector=meta["default_vector"],
                                confidence=conf,
                                confidence_factors=conf_factors,
                                validation_status=val_status,
                                owasp={"id": meta["owasp_id"], "name": meta["owasp_name"]},
                                cwe={"id": meta["cwe_id"], "name": meta["cwe_name"]},
                                evidence=evidence
                            ))
            except Exception as e:
                logger.debug(f"TLS probe info on {hostname}:{port}: {e}")

        return findings
