"""
Backward-compatible SSRF scanner wrapper.
Preserves legacy scan_ssrf(url) signature with multi-param testing.
"""
import requests
from backend.scanners.ssrf import SSRF_PARAM_CANDIDATES, SSRF_PROBES

def scan_ssrf(url: str) -> bool:
    """Scans a URL for potential SSRF vulnerabilities."""
    test_payload = "http://127.0.0.1:80/aegis_ssrf_test"
    params = ["redirect", "url", "dest", "proxy"]

    for param in params:
        try:
            target_url = f"{url}?{param}={requests.utils.quote(test_payload)}" if "?" not in url else f"{url}&{param}={requests.utils.quote(test_payload)}"
            response = requests.get(target_url, timeout=10.0)
            text_lower = response.text.lower()
            if "localhost" in text_lower or "127.0.0.1" in text_lower or "internal" in text_lower:
                print(f"[!] Potential SSRF vulnerability detected on parameter '{param}'!")
                return True
        except requests.RequestException as e:
            print(f"Error scanning URL parameter '{param}': {e}")
            break

    print("[+] No SSRF vulnerability found.")
    return False

if __name__ == "__main__":
    import sys
    test_target = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    scan_ssrf(test_target)
