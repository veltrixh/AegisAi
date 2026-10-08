from typing import Dict, Any, Optional

CWE_DATABASE: Dict[str, Dict[str, str]] = {
    "CWE-89": {
        "id": "CWE-89",
        "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "description": "The product constructs an SQL command using externally-influenced input, allowing an attacker to alter the query logic and bypass authorization or access/modify unauthorized data.",
        "url": "https://cwe.mitre.org/data/definitions/89.html"
    },
    "CWE-79": {
        "id": "CWE-79",
        "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "description": "The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
        "url": "https://cwe.mitre.org/data/definitions/79.html"
    },
    "CWE-352": {
        "id": "CWE-352",
        "name": "Cross-Site Request Forgery (CSRF)",
        "description": "The web application does not sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.",
        "url": "https://cwe.mitre.org/data/definitions/352.html"
    },
    "CWE-918": {
        "id": "CWE-918",
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
        "url": "https://cwe.mitre.org/data/definitions/918.html"
    },
    "CWE-1021": {
        "id": "CWE-1021",
        "name": "Improper Restriction of Rendered UI Layers or Frames ('Clickjacking')",
        "description": "The web application does not restrict framing of its interface, allowing an attacker to render the page within an invisible or transparent frame to trick users into performing unintended actions.",
        "url": "https://cwe.mitre.org/data/definitions/1021.html"
    },
    "CWE-693": {
        "id": "CWE-693",
        "name": "Protection Mechanism Failure",
        "description": "The product does not adequately provide or maintain a protection mechanism such as defensive HTTP response headers (CSP, HSTS, X-Content-Type-Options).",
        "url": "https://cwe.mitre.org/data/definitions/693.html"
    },
    "CWE-319": {
        "id": "CWE-319",
        "name": "Cleartext Transmission of Sensitive Information",
        "description": "The product transmits sensitive data in cleartext or over an unencrypted channel (HTTP or insecure TLS protocol).",
        "url": "https://cwe.mitre.org/data/definitions/319.html"
    },
    "CWE-306": {
        "id": "CWE-306",
        "name": "Missing Authentication for Critical Function",
        "description": "The product does not authenticate user identities for critical functions or sensitive API endpoints.",
        "url": "https://cwe.mitre.org/data/definitions/306.html"
    },
    "CWE-942": {
        "id": "CWE-942",
        "name": "Permissive Cross-Domain Policy with Untrusted Domains (CORS)",
        "description": "The web application specifies an overly permissive Cross-Origin Resource Sharing (CORS) policy (e.g. Access-Control-Allow-Origin: * with credentials).",
        "url": "https://cwe.mitre.org/data/definitions/942.html"
    },
    "CWE-200": {
        "id": "CWE-200",
        "name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "description": "The product reveals sensitive data (database schema, internal server errors, software versions) in error messages or API responses.",
        "url": "https://cwe.mitre.org/data/definitions/200.html"
    }
}

def get_cwe_info(cwe_id: str) -> Optional[Dict[str, str]]:
    """Fetches CWE metadata by ID (e.g. CWE-89 or 89)."""
    norm = cwe_id if cwe_id.startswith("CWE-") else f"CWE-{cwe_id}"
    return CWE_DATABASE.get(norm)
