import uuid
from typing import List, Dict, Any
from backend.models.finding import FindingModel
from backend.models.attack_path import VulnerabilityCorrelation
from backend.utils.logger import logger

def _is_xss(f: FindingModel) -> bool:
    t = f.type.lower()
    return "xss" in t or "cross-site scripting" in t or "cross site scripting" in t

class VulnerabilityCorrelationEngine:
    """
    Correlates multiple findings to identify compounded attack surfaces,
    synergistic vulnerabilities, and multi-vector exposure chains.
    """

    @classmethod
    def correlate(cls, findings: List[FindingModel]) -> List[VulnerabilityCorrelation]:
        correlations: List[VulnerabilityCorrelation] = []

        # 1. XSS + Insecure Cookies (Missing HttpOnly) + Missing CSP
        has_xss = any(_is_xss(f) for f in findings)
        cookie_finding = next((f for f in findings if "cookie" in f.type.lower() or "httponly" in str(f.evidence.behavioral_changes).lower()), None)
        headers_finding = next((f for f in findings if "security headers" in f.type.lower() or "content-security-policy" in str(f.evidence.behavioral_changes).lower()), None)

        if has_xss and (cookie_finding or headers_finding):
            involved = [f.finding_id for f in findings if _is_xss(f)]
            if cookie_finding and cookie_finding.finding_id not in involved:
                involved.append(cookie_finding.finding_id)
            if headers_finding and headers_finding.finding_id not in involved:
                involved.append(headers_finding.finding_id)

            correlations.append(VulnerabilityCorrelation(
                correlation_id=f"CORR-{uuid.uuid4().hex[:6].upper()}",
                relationship_type="BROWSER_SESSION_COMPROMISE_SYNERGY",
                findings_involved=involved,
                confidence=95.0,
                reason=(
                    "Cross-Site Scripting (XSS) is compounded by missing HttpOnly cookie protections and/or "
                    "missing Content-Security-Policy (CSP). An attacker can inject arbitrary JavaScript to exfiltrate "
                    "unprotected authentication cookies and establish persistent account takeover."
                ),
                compounded_risk_score=9.5
            ))

        # 2. SSRF + Internal or Cloud Metadata Exposure
        ssrf_finding = next((f for f in findings if "ssrf" in f.type.lower() or "server-side request forgery" in f.type.lower()), None)
        api_unauth = next((f for f in findings if "api" in f.type.lower() and "auth" in f.title.lower()), None)

        if ssrf_finding:
            involved = [ssrf_finding.finding_id]
            reason = "Server-Side Request Forgery detected."
            if api_unauth:
                involved.append(api_unauth.finding_id)
                reason += (
                    " SSRF combined with unauthenticated internal API endpoints allows external threat actors "
                    "to pivot through the web server to access private microservices and privileged backend endpoints."
                )
                compounded_risk = 9.7
            else:
                reason += " SSRF probe exposed internal infrastructure or cloud instance metadata (IMDSv1/v2)."
                compounded_risk = 9.2

            correlations.append(VulnerabilityCorrelation(
                correlation_id=f"CORR-{uuid.uuid4().hex[:6].upper()}",
                relationship_type="INTERNAL_NETWORK_PIVOT_CHAIN",
                findings_involved=involved,
                confidence=92.0,
                reason=reason,
                compounded_risk_score=compounded_risk
            ))

        # 3. SQLi + Database Error Disclosure
        sqli_finding = next((f for f in findings if "sql" in f.type.lower()), None)
        if sqli_finding and sqli_finding.evidence.error_signature:
            correlations.append(VulnerabilityCorrelation(
                correlation_id=f"CORR-{uuid.uuid4().hex[:6].upper()}",
                relationship_type="DATABASE_SCHEMA_FINGERPRINT_AND_EXFILTRATION",
                findings_involved=[sqli_finding.finding_id],
                confidence=98.0,
                reason=(
                    f"SQL Injection in parameter '{sqli_finding.parameter}' is coupled with active database error disclosure "
                    f"({sqli_finding.evidence.error_signature}). Verbose syntax errors reveal underlying database dialect and table architecture, "
                    "enabling rapid automated schema extraction and data exfiltration."
                ),
                compounded_risk_score=9.8
            ))

        # 4. CSRF + Missing SameSite Cookies
        csrf_finding = next((f for f in findings if "csrf" in f.type.lower()), None)
        if csrf_finding and cookie_finding:
            correlations.append(VulnerabilityCorrelation(
                correlation_id=f"CORR-{uuid.uuid4().hex[:6].upper()}",
                relationship_type="UNAUTHENTICATED_STATE_MUTATION_CHAIN",
                findings_involved=[csrf_finding.finding_id, cookie_finding.finding_id],
                confidence=89.0,
                reason=(
                    "Forms lack anti-CSRF tokens and session cookies lack strict SameSite isolation. "
                    "Third-party sites can trigger state-changing HTTP requests with ambient session credentials."
                ),
                compounded_risk_score=8.4
            ))

        # 5. API Missing Auth + Excessive Data Exposure
        api_exposure = next((f for f in findings if "excessive data exposure" in f.type.lower()), None)
        if api_unauth and api_exposure:
            correlations.append(VulnerabilityCorrelation(
                correlation_id=f"CORR-{uuid.uuid4().hex[:6].upper()}",
                relationship_type="UNRESTRICTED_PII_EXFILTRATION",
                findings_involved=[api_unauth.finding_id, api_exposure.finding_id],
                confidence=94.0,
                reason=(
                    "Unauthenticated API endpoints coupled with overly broad schema responses expose sensitive user attributes "
                    "(passwords, tokens, or PII) directly to unauthenticated Internet clients."
                ),
                compounded_risk_score=9.1
            ))

        logger.info(f"Vulnerability correlation identified {len(correlations)} compounded attack relationships.")
        return correlations
