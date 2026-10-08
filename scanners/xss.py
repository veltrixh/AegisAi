"""
Backward-compatible XSS scanner wrapper.
Preserves legacy scan_xss(url) signature with multi-vector detection.
"""
import requests
from backend.scanners.xss import XSS_PROBES

def scan_xss(url: str) -> bool:
    """Scans a URL for basic and contextual XSS vulnerabilities."""
    for probe in XSS_PROBES:
        payload = probe["payload"]
        sig = probe["signature"]
        try:
            target_url = f"{url}?q={requests.utils.quote(payload)}" if "?" not in url else f"{url}&q={requests.utils.quote(payload)}"
            response = requests.get(target_url, timeout=10.0)
            if sig in response.text and not "&lt;script&gt;" in response.text:
                print(f"[!] Potential XSS vulnerability detected! (Payload: {payload})")
                return True
        except requests.RequestException as e:
            print(f"Error scanning URL for XSS: {e}")
            break

    print("[+] No XSS vulnerability found.")
    return False

if __name__ == "__main__":
    import sys
    test_target = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    scan_xss(test_target)
