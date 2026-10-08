"""
Backward-compatible CSRF scanner wrapper.
Preserves legacy scan_csrf(url) signature with enhanced token checking.
"""
import requests
from bs4 import BeautifulSoup
from backend.scanners.csrf import CSRF_TOKEN_NAMES

def scan_csrf(url: str) -> bool:
    """Scans a URL for potential CSRF vulnerabilities in forms."""
    try:
        response = requests.get(url, timeout=10.0)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        if not forms:
            print("[+] No forms found to evaluate for CSRF.")
            return False

        csrf_vulnerable = False
        for form in forms:
            has_token = False
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = (inp.get('name') or '').lower()
                if any(t in name for t in CSRF_TOKEN_NAMES):
                    has_token = True
                    break

            if not has_token:
                method = form.get('method', 'GET').upper()
                print(f"[!] Potential CSRF vulnerability: {method} form lacks CSRF token.")
                csrf_vulnerable = True

        if not csrf_vulnerable:
            print("[+] No CSRF vulnerability found.")
        return csrf_vulnerable
    except requests.RequestException as e:
        print(f"Error scanning URL: {e}")
        return False

if __name__ == "__main__":
    import sys
    test_target = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    scan_csrf(test_target)
