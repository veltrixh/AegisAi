from typing import Dict, Any, Optional

OWASP_TOP_10_2021: Dict[str, Dict[str, str]] = {
    "A01:2021": {
        "id": "A01:2021",
        "name": "Broken Access Control",
        "description": "Restrictions on what authenticated users are allowed to do are not properly enforced.",
        "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
    },
    "A02:2021": {
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "description": "Failures related to cryptography (or lack thereof), leading to sensitive data exposure or key compromise.",
        "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
    },
    "A03:2021": {
        "id": "A03:2021",
        "name": "Injection",
        "description": "User-supplied data is not validated, filtered, or sanitized by the application before execution.",
        "url": "https://owasp.org/Top10/A03_2021-Injection/"
    },
    "A04:2021": {
        "id": "A04:2021",
        "name": "Insecure Design",
        "description": "Risks related to design and architectural flaws, requiring threat modeling and secure design patterns.",
        "url": "https://owasp.org/Top10/A04_2021-Insecure_Design/"
    },
    "A05:2021": {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": "Missing security hardening, default credentials, improperly configured HTTP headers, or verbose error pages.",
        "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
    },
    "A06:2021": {
        "id": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "description": "Using client-side or server-side libraries with known CVEs or unsupported versions.",
        "url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"
    },
    "A07:2021": {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "description": "Flaws in session management, credential stuffing vulnerability, or missing MFA.",
        "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
    },
    "A08:2021": {
        "id": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "description": "Code and infrastructure that does not protect against integrity violations (untrusted deserialization, CI/CD compromise).",
        "url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
    },
    "A09:2021": {
        "id": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "description": "Insufficient logging, breach detection failure, or missing real-time alerts.",
        "url": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"
    },
    "A10:2021": {
        "id": "A10:2021",
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "Web applications fetching a remote resource without validating the user-supplied URL.",
        "url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"
    }
}

OWASP_API_TOP_10_2023: Dict[str, Dict[str, str]] = {
    "API1:2023": {"id": "API1:2023", "name": "Broken Object Level Authorization (BOLA)"},
    "API2:2023": {"id": "API2:2023", "name": "Broken Authentication"},
    "API3:2023": {"id": "API3:2023", "name": "Broken Object Property Level Authorization"},
    "API4:2023": {"id": "API4:2023", "name": "Unrestricted Resource Consumption"},
    "API5:2023": {"id": "API5:2023", "name": "Broken Function Level Authorization (BFLA)"},
    "API6:2023": {"id": "API6:2023", "name": "Unrestricted Access to Sensitive Business Flows"},
    "API7:2023": {"id": "API7:2023", "name": "Server Side Request Forgery"},
    "API8:2023": {"id": "API8:2023", "name": "Security Misconfiguration"},
    "API9:2023": {"id": "API9:2023", "name": "Improper Inventory Management"},
    "API10:2023": {"id": "API10:2023", "name": "Unsafe Consumption of APIs"},
}

def get_owasp_info(key: str) -> Optional[Dict[str, str]]:
    """Retrieves full OWASP metadata by code (e.g. A03:2021 or A03)."""
    if key in OWASP_TOP_10_2021:
        return OWASP_TOP_10_2021[key]
    for k, v in OWASP_TOP_10_2021.items():
        if key in k:
            return v
    return None
