import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple

METADATA_IPS = {"169.254.169.254", "metadata.google.internal"}

def is_private_or_loopback_ip(ip_str: str) -> bool:
    """Checks whether an IP address is loopback, link-local, private, or reserved."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast
    except ValueError:
        return False

def validate_target_url(url: str, allow_local: bool = True) -> Tuple[bool, str]:
    """
    Validates target URL scheme, hostname, and accessibility safely.
    Returns (is_valid, error_message_or_normalized_url).
    """
    if not url:
        return False, "Target URL cannot be empty."

    url = url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        # Default to https or http
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"Invalid URL syntax: {e}"

    if parsed.scheme not in ("http", "https"):
        return False, f"Unsupported scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "Target URL must contain a valid hostname or IP address."

    if parsed.username or parsed.password:
        return False, "Target URL must not contain embedded credentials."

    # Prevent access to AWS/GCP/Azure instance metadata endpoints from scanner orchestrator
    if hostname in METADATA_IPS:
        return False, f"Scanning cloud metadata endpoint '{hostname}' is prohibited."

    if not allow_local:
        try:
            resolved_ip = socket.gethostbyname(hostname)
            if is_private_or_loopback_ip(resolved_ip):
                return False, f"Resolved IP {resolved_ip} is a private/loopback address and allow_local is False."
        except socket.gaierror:
            pass  # Let request layer handle connection failures gracefully

    # Normalized URL
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    return True, normalized
