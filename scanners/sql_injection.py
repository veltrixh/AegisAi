"""
Backward-compatible SQL Injection scanner wrapper.
Preserves legacy scan_sql_injection(url) signature while integrating
the upgraded multi-payload and deterministic signature detection.
"""
import requests
import asyncio
from typing import Optional
from backend.scanners.sqli import SQL_ERROR_PATTERNS, SQLI_PAYLOADS, SQLInjectionScanner
from backend.utils.http_client import AsyncScannerClient

def scan_sql_injection(url: str) -> bool:
    """Scans a URL for SQL Injection vulnerabilities with enhanced error signature matching."""
    detected = False
    for probe in SQLI_PAYLOADS:
        payload = probe["payload"]
        try:
            target_url = f"{url}?id={requests.utils.quote(payload)}" if "?" not in url else f"{url}&id={requests.utils.quote(payload)}"
            response = requests.get(target_url, timeout=10.0)
            text_lower = response.text.lower()

            for db, patterns in SQL_ERROR_PATTERNS.items():
                for p in patterns:
                    if p.search(response.text):
                        print(f"[!] Potential SQL Injection detected! ({db} signature)")
                        return True

            if "sql syntax" in text_lower or "mysql" in text_lower or "syntax error" in text_lower:
                print("[!] Potential SQL Injection vulnerability detected!")
                return True
        except requests.RequestException as e:
            print(f"Error scanning URL for SQL Injection: {e}")
            break

    print("[+] No SQL Injection vulnerability found.")
    return False

if __name__ == "__main__":
    import sys
    test_target = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    scan_sql_injection(test_target)
