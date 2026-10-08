import uuid
from typing import Dict, Any, List
from bs4 import BeautifulSoup
from backend.scanners.base import BaseScanner
from backend.models.finding import FindingModel
from backend.core.evidence import EvidenceCollector
from backend.ai.confidence import ConfidenceEngine
from backend.core.risk_engine import RiskEngine
from backend.intelligence.knowledge import get_vulnerability_metadata
from backend.utils.http_client import ScannerResponse, AsyncScannerClient
from backend.utils.logger import logger

CSRF_TOKEN_NAMES = {
    "csrf", "csrf_token", "csrftoken", "_csrf", "_token", "authenticity_token",
    "xsrf", "xsrf_token", "_xsrf", "anti_forgery_token"
}

class CSRFScanner(BaseScanner):
    """
    Deterministic Cross-Site Request Forgery (CSRF) Scanner.
    Analyzes forms, state-changing endpoints, token presence, and SameSite cookie protection.
    """
    name = "Deterministic CSRF Engine"
    vulnerability_type = "csrf"
    category = "active"

    async def scan(self, target: str, context: Dict[str, Any]) -> List[FindingModel]:
        logger.info(f"Scanning target for CSRF: {target}")
        findings: List[FindingModel] = []

        if not self.client:
            self.client = AsyncScannerClient()

        baseline: ScannerResponse = context.get("baseline")
        if not baseline:
            baseline = await self.client.get(target)

        # Discovered forms from discovery scanner
        forms = context.get("discovered_forms", [])
        if not forms and baseline.text:
            try:
                soup = BeautifulSoup(baseline.text, "html.parser")
                for f in soup.find_all("form"):
                    method = f.get("method", "GET").upper()
                    action = f.get("action", target)
                    inputs = []
                    for inp in f.find_all(["input", "textarea", "select"]):
                        name = inp.get("name")
                        if name:
                            inputs.append({"name": name, "type": inp.get("type", "text")})
                    has_token = any(
                        any(token in (inp["name"] or "").lower() for token in CSRF_TOKEN_NAMES)
                        for inp in inputs
                    )
                    forms.append({
                        "url": action,
                        "method": method,
                        "inputs": inputs,
                        "has_csrf_token": has_token
                    })
            except Exception as e:
                logger.debug(f"CSRF form parse error: {e}")

        # Check cookies for SameSite
        set_cookie = baseline.headers.get("set-cookie", "").lower()
        samesite_protected = "samesite=strict" in set_cookie or "samesite=lax" in set_cookie

        for form in forms:
            is_state_changing = form.get("method") in ("POST", "PUT", "DELETE")
            has_token = form.get("has_csrf_token", False)

            if not has_token:
                # If it's a state-changing POST form without token and without SameSite cookie
                rule_id = "csrf_missing_token_state_changing" if is_state_changing else "csrf_missing_token_get"
                meta = get_vulnerability_metadata("csrf")

                evidence = EvidenceCollector.capture(
                    baseline=baseline,
                    test_response=baseline,
                    test_request_data={
                        "method": form.get("method", "GET"),
                        "url": form.get("url", target),
                        "params": {inp["name"]: "test_val" for inp in form.get("inputs", [])}
                    },
                    error_signature=None,
                    detection_rule=rule_id,
                    payload_category="csrf_protection",
                    reproducible=True,
                    reproduction_count=1,
                    extra_behavior={
                        "form_action": form.get("url"),
                        "form_method": form.get("method"),
                        "input_count": len(form.get("inputs", [])),
                        "missing_anti_csrf_token": True,
                        "samesite_cookie_present": samesite_protected
                    }
                )

                conf, conf_factors, val_status = ConfidenceEngine.evaluate(evidence, rule_id)
                # If samesite is present, reduce severity/risk slightly
                cvss_score = meta["default_cvss"] if is_state_changing else 4.3
                if samesite_protected:
                    cvss_score = max(3.5, cvss_score - 1.5)

                risk = RiskEngine.calculate_finding_risk(cvss_score, conf)

                finding = FindingModel(
                    finding_id=f"CSRF-{uuid.uuid4().hex[:6].upper()}",
                    type="Cross-Site Request Forgery (CSRF)",
                    title=f"Form Lacks Anti-CSRF Protection ({form.get('method')} {form.get('url')})",
                    target=form.get("url", target),
                    parameter="Form Token / Headers",
                    method=form.get("method", "POST"),
                    severity="HIGH" if risk >= 7.0 else "MEDIUM",
                    risk_score=risk,
                    cvss=cvss_score,
                    cvss_vector=meta["default_vector"],
                    confidence=conf,
                    confidence_factors=conf_factors,
                    validation_status=val_status,
                    owasp={"id": meta["owasp_id"], "name": meta["owasp_name"]},
                    cwe={"id": meta["cwe_id"], "name": meta["cwe_name"]},
                    evidence=evidence
                )
                findings.append(finding)
                logger.info(f"Detected CSRF vulnerability in form action {form.get('url')} (Risk: {risk})")

        return findings
