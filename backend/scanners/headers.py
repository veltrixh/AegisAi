from typing import Dict, Any, List
from backend.scanners.base import BaseScanner
from backend.models.finding import FindingModel
from backend.models.evidence import RequestEvidence, ResponseEvidence
from backend.core.evidence import EvidenceCollector
from backend.ai.confidence import ConfidenceEngine
from backend.core.risk_engine import RiskEngine
from backend.intelligence.knowledge import get_vulnerability_metadata
from backend.utils.http_client import ScannerResponse, AsyncScannerClient
from backend.utils.sanitizer import sanitize_headers
from backend.utils.logger import logger
import uuid

class SecurityHeadersScanner(BaseScanner):
    """
    Passive Security Headers and Cookie Configuration Analyzer.
    Evaluates HTTP response headers for missing defense-in-depth protections:
    CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
    Permissions-Policy, Cookie flags (Secure, HttpOnly, SameSite), and CORS.
    """
    name = "Passive Security Headers & Cookie Scanner"
    vulnerability_type = "missing_security_headers"
    category = "passive"

    REQUIRED_HEADERS = {
        "content-security-policy": {
            "name": "Content-Security-Policy",
            "desc": "Mitigates Cross-Site Scripting (XSS) and data injection attacks by restricting executable script origins.",
            "cvss": 5.3
        },
        "strict-transport-security": {
            "name": "Strict-Transport-Security (HSTS)",
            "desc": "Enforces TLS/HTTPS communication and protects against SSL stripping attacks.",
            "cvss": 4.8
        },
        "x-frame-options": {
            "name": "X-Frame-Options",
            "desc": "Protects against clickjacking attacks by preventing frame/iframe embedding.",
            "cvss": 5.0
        },
        "x-content-type-options": {
            "name": "X-Content-Type-Options",
            "desc": "Prevents MIME-type sniffing which can lead to script execution in uploaded files.",
            "cvss": 3.7
        },
        "referrer-policy": {
            "name": "Referrer-Policy",
            "desc": "Controls information sent in Referer header to protect sensitive URL tokens and parameters.",
            "cvss": 3.1
        },
        "permissions-policy": {
            "name": "Permissions-Policy",
            "desc": "Restricts browser feature access (camera, microphone, geolocation) for third-party embeds.",
            "cvss": 2.5
        }
    }

    async def scan(self, target: str, context: Dict[str, Any]) -> List[FindingModel]:
        logger.info(f"Analyzing security headers for: {target}")
        findings: List[FindingModel] = []

        baseline: ScannerResponse = context.get("baseline")
        if not baseline:
            if not self.client:
                self.client = AsyncScannerClient()
            baseline = await self.client.get(target)

        headers = {k.lower(): v for k, v in baseline.headers.items()}

        # 1. Check Missing HTTP Headers
        missing = []
        for header_key, meta in self.REQUIRED_HEADERS.items():
            if header_key not in headers:
                missing.append(meta["name"])

        if missing:
            rule_id = "security_headers_passive"
            meta = get_vulnerability_metadata("missing_security_headers")
            cvss_score = 5.3 if "Content-Security-Policy" in missing else 4.0

            evidence = EvidenceCollector.capture(
                baseline=baseline,
                test_response=baseline,
                test_request_data={"method": "GET", "url": target, "headers": {}},
                error_signature=None,
                detection_rule=rule_id,
                payload_category="passive_headers",
                reproducible=True,
                extra_behavior={"missing_headers": missing, "present_headers": list(headers.keys())}
            )

            conf, conf_factors, val_status = ConfidenceEngine.evaluate(evidence, rule_id)
            risk = RiskEngine.calculate_finding_risk(cvss_score, conf)

            findings.append(FindingModel(
                finding_id=f"HDR-{uuid.uuid4().hex[:6].upper()}",
                type="Missing Security Headers",
                title=f"Missing Defensive Headers ({', '.join(missing[:3])})",
                target=target,
                parameter="HTTP Response Headers",
                method="GET",
                severity="MEDIUM" if cvss_score >= 5.0 else "LOW",
                risk_score=risk,
                cvss=cvss_score,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence=conf,
                confidence_factors=conf_factors,
                validation_status=val_status,
                owasp={"id": meta["owasp_id"], "name": meta["owasp_name"]},
                cwe={"id": meta["cwe_id"], "name": meta["cwe_name"]},
                evidence=evidence
            ))

        # 2. Check Cookie Attributes
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            cookie_issues = []
            if "httponly" not in set_cookie.lower():
                cookie_issues.append("Missing HttpOnly flag (accessible to JavaScript / XSS)")
            if "secure" not in set_cookie.lower() and target.startswith("https"):
                cookie_issues.append("Missing Secure flag (transmissible via plain HTTP)")
            if "samesite" not in set_cookie.lower():
                cookie_issues.append("Missing SameSite attribute (CSRF risk)")

            if cookie_issues:
                meta = get_vulnerability_metadata("missing_security_headers")
                evidence = EvidenceCollector.capture(
                    baseline=baseline,
                    test_response=baseline,
                    test_request_data={"method": "GET", "url": target, "headers": {}},
                    error_signature=None,
                    detection_rule="security_headers_passive",
                    payload_category="cookie_security",
                    reproducible=True,
                    extra_behavior={"cookie_flaws": cookie_issues}
                )
                conf, conf_factors, val_status = ConfidenceEngine.evaluate(evidence, "security_headers_passive")
                risk = RiskEngine.calculate_finding_risk(5.0, conf)

                findings.append(FindingModel(
                    finding_id=f"CK-{uuid.uuid4().hex[:6].upper()}",
                    type="Insecure Cookie Attributes",
                    title="Insecure Cookie Flags Detected",
                    target=target,
                    parameter="Set-Cookie Header",
                    method="GET",
                    severity="MEDIUM",
                    risk_score=risk,
                    cvss=5.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                    confidence=conf,
                    confidence_factors=conf_factors,
                    validation_status=val_status,
                    owasp={"id": "A05:2021", "name": "Security Misconfiguration"},
                    cwe={"id": "CWE-693", "name": "Protection Mechanism Failure"},
                    evidence=evidence
                ))

        # 3. Check CORS Misconfiguration
        allow_origin = headers.get("access-control-allow-origin", "")
        allow_credentials = headers.get("access-control-allow-credentials", "").lower()
        if allow_origin == "*" or (allow_origin and allow_credentials == "true"):
            meta = get_vulnerability_metadata("cors_misconfiguration")
            evidence = EvidenceCollector.capture(
                baseline=baseline,
                test_response=baseline,
                test_request_data={"method": "GET", "url": target, "headers": {"Origin": "https://evil.attacker.com"}},
                error_signature=None,
                detection_rule="security_headers_passive",
                payload_category="cors_misconfiguration",
                reproducible=True,
                extra_behavior={"allow_origin": allow_origin, "allow_credentials": allow_credentials}
            )
            conf, conf_factors, val_status = ConfidenceEngine.evaluate(evidence, "security_headers_passive")
            risk = RiskEngine.calculate_finding_risk(meta["default_cvss"], conf)

            findings.append(FindingModel(
                finding_id=f"CORS-{uuid.uuid4().hex[:6].upper()}",
                type="CORS Misconfiguration",
                title="Overly Permissive Cross-Origin Resource Sharing (CORS)",
                target=target,
                parameter="Access-Control-Allow-Origin",
                method="GET",
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

        return findings
