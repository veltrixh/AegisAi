from typing import Dict, Any, Optional
from backend.intelligence.owasp import OWASP_TOP_10_2021
from backend.intelligence.cwe import CWE_DATABASE
from backend.intelligence.cvss import calculate_cvss_v3

VULNERABILITY_KNOWLEDGE_BASE: Dict[str, Dict[str, Any]] = {
    "sql_injection": {
        "title": "SQL Injection",
        "category": "Injection",
        "owasp_id": "A03:2021",
        "owasp_name": "Injection",
        "cwe_id": "CWE-89",
        "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
        "wstg_id": "WSTG-INPV-05",
        "capec_id": "CAPEC-66",
        "default_cvss": 8.8,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "impact_description": "Arbitrary database access, unauthorized extraction of confidential records, alteration or destruction of tables, potential OS command execution via db extensions.",
        "cvss_params": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "scope": "U", "c": "H", "i": "H", "a": "H"}
    },
    "xss_reflected": {
        "title": "Reflected Cross-Site Scripting (XSS)",
        "category": "Injection",
        "owasp_id": "A03:2021",
        "owasp_name": "Injection",
        "cwe_id": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation",
        "wstg_id": "WSTG-INPV-01",
        "capec_id": "CAPEC-63",
        "default_cvss": 7.1,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "impact_description": "Execution of arbitrary client-side JavaScript in victim browser, session token theft, UI redressing, and credential harvesting.",
        "cvss_params": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "scope": "C", "c": "L", "i": "L", "a": "N"}
    },
    "csrf": {
        "title": "Cross-Site Request Forgery (CSRF)",
        "category": "Broken Access Control",
        "owasp_id": "A01:2021",
        "owasp_name": "Broken Access Control",
        "cwe_id": "CWE-352",
        "cwe_name": "Cross-Site Request Forgery (CSRF)",
        "wstg_id": "WSTG-SESS-05",
        "capec_id": "CAPEC-62",
        "default_cvss": 6.5,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        "impact_description": "Forced execution of unauthorized state-changing operations (email change, password reset, funds transfer) on behalf of authenticated victim.",
        "cvss_params": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "scope": "U", "c": "N", "i": "H", "a": "N"}
    },
    "ssrf": {
        "title": "Server-Side Request Forgery (SSRF)",
        "category": "Server-Side Request Forgery",
        "owasp_id": "A10:2021",
        "owasp_name": "Server-Side Request Forgery (SSRF)",
        "cwe_id": "CWE-918",
        "cwe_name": "Server-Side Request Forgery (SSRF)",
        "wstg_id": "WSTG-INPV-19",
        "capec_id": "CAPEC-664",
        "default_cvss": 8.6,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "impact_description": "Access to internal microservices, cloud provider instance metadata (IAM credentials), port scanning of perimeter networks, and internal data leakage.",
        "cvss_params": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "scope": "C", "c": "H", "i": "N", "a": "N"}
    },
    "missing_security_headers": {
        "title": "Missing Security Headers",
        "category": "Security Misconfiguration",
        "owasp_id": "A05:2021",
        "owasp_name": "Security Misconfiguration",
        "cwe_id": "CWE-693",
        "cwe_name": "Protection Mechanism Failure",
        "wstg_id": "WSTG-CONF-07",
        "capec_id": "CAPEC-224",
        "default_cvss": 5.3,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "impact_description": "Lack of browser defense-in-depth protections against MIME-sniffing, clickjacking, and cross-site scripting attacks.",
        "cvss_params": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "scope": "U", "c": "L", "i": "N", "a": "N"}
    },
    "cors_misconfiguration": {
        "title": "Overly Permissive CORS Policy",
        "category": "Security Misconfiguration",
        "owasp_id": "A05:2021",
        "owasp_name": "Security Misconfiguration",
        "cwe_id": "CWE-942",
        "cwe_name": "Permissive Cross-Domain Policy with Untrusted Domains",
        "wstg_id": "WSTG-CONF-07",
        "capec_id": "CAPEC-63",
        "default_cvss": 6.5,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "impact_description": "Malicious external websites can read authenticated cross-origin response payloads and steal private data.",
        "cvss_params": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "scope": "U", "c": "H", "i": "N", "a": "N"}
    },
    "tls_misconfiguration": {
        "title": "TLS / Insecure Transport Configuration",
        "category": "Cryptographic Failures",
        "owasp_id": "A02:2021",
        "owasp_name": "Cryptographic Failures",
        "cwe_id": "CWE-319",
        "cwe_name": "Cleartext Transmission of Sensitive Information",
        "wstg_id": "WSTG-CRYP-01",
        "capec_id": "CAPEC-94",
        "default_cvss": 5.9,
        "default_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "impact_description": "Cleartext transport or weak SSL/TLS allows passive interception or man-in-the-middle attacks on network traffic.",
        "cvss_params": {"av": "N", "ac": "H", "pr": "N", "ui": "N", "scope": "U", "c": "H", "i": "N", "a": "N"}
    },
    "api_missing_auth": {
        "title": "API Endpoint Lacks Authentication",
        "category": "Broken Access Control",
        "owasp_id": "A01:2021",
        "owasp_name": "Broken Access Control",
        "cwe_id": "CWE-306",
        "cwe_name": "Missing Authentication for Critical Function",
        "wstg_id": "WSTG-ATHN-01",
        "capec_id": "CAPEC-115",
        "default_cvss": 7.5,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "impact_description": "Unauthenticated access to internal API methods permitting sensitive object retrieval or mutation.",
        "cvss_params": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "scope": "U", "c": "H", "i": "N", "a": "N"}
    },
    "api_excessive_exposure": {
        "title": "API Excessive Data Exposure",
        "category": "Security Misconfiguration",
        "owasp_id": "A01:2021",
        "owasp_name": "Broken Access Control",
        "cwe_id": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "wstg_id": "WSTG-INFO-05",
        "capec_id": "CAPEC-37",
        "default_cvss": 5.3,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "impact_description": "API responses return unnecessary properties or internal implementation fields containing PII or sensitive keys.",
        "cvss_params": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "scope": "U", "c": "L", "i": "N", "a": "N"}
    }
}

def get_vulnerability_metadata(vuln_type: str) -> Dict[str, Any]:
    """Retrieves full standardized metadata for a vulnerability type."""
    norm = vuln_type.lower().replace(" ", "_").replace("-", "_")
    for key, data in VULNERABILITY_KNOWLEDGE_BASE.items():
        if key in norm or norm in key:
            return data
    # Fallback default
    return {
        "title": vuln_type.title(),
        "category": "Security Finding",
        "owasp_id": "A05:2021",
        "owasp_name": "Security Misconfiguration",
        "cwe_id": "CWE-693",
        "cwe_name": "Protection Mechanism Failure",
        "wstg_id": "WSTG-GEN-01",
        "capec_id": "CAPEC-1",
        "default_cvss": 5.0,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "impact_description": "Potential vulnerability identified requiring security verification.",
        "cvss_params": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "scope": "U", "c": "L", "i": "N", "a": "N"}
    }
