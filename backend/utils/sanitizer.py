import re
from typing import Dict, Any, Union

SENSITIVE_FIELD_NAMES = {
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "access_token", "auth_token", "token", "authorization",
    "cookie", "set-cookie", "x-api-key", "session", "sessionid",
    "phpsessid", "jsessionid", "csrf_token", "authenticity_token"
}

def sanitize_dict_or_str(data: Union[Dict, str, Any]) -> Any:
    """Recursively redacts sensitive values in dicts, lists, or strings."""
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(sens in k_lower for sens in SENSITIVE_FIELD_NAMES):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_dict_or_str(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_dict_or_str(item) for item in data]
    elif isinstance(data, str):
        return sanitize_string(data)
    return data

def sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Sanitizes HTTP headers by masking authorization tokens, session cookies, and API keys."""
    cleaned = {}
    for k, v in headers.items():
        k_lower = k.lower()
        if k_lower in ("authorization", "proxy-authorization"):
            cleaned[k] = "Bearer [REDACTED]" if "bearer" in v.lower() else "[REDACTED]"
        elif k_lower in ("cookie", "set-cookie"):
            # Preserve cookie keys, mask values
            parts = v.split(";")
            masked_parts = []
            for part in parts:
                if "=" in part:
                    cname, _ = part.split("=", 1)
                    masked_parts.append(f"{cname.strip()}=[REDACTED]")
                else:
                    masked_parts.append(part.strip())
            cleaned[k] = "; ".join(masked_parts)
        elif any(sens in k_lower for sens in ("api-key", "token", "secret", "auth")):
            cleaned[k] = "[REDACTED]"
        else:
            cleaned[k] = v
    return cleaned

def sanitize_string(text: str) -> str:
    """Scans and masks common token / key formats within raw text or snippets."""
    if not text:
        return ""
    # Mask JWTs
    text = re.sub(r'ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', '[JWT_REDACTED]', text)
    # Mask Bearer tokens
    text = re.sub(r'(?i)(bearer\s+)[A-Za-z0-9_\-\.]{15,}', r'\1[REDACTED]', text)
    # Mask common API Key formats (sk_live, AIzaSy, etc.)
    text = re.sub(r'(sk_live_[0-9a-zA-Z]{24})', '[API_KEY_REDACTED]', text)
    text = re.sub(r'(AIzaSy[0-9A-Za-z-_]{33})', '[API_KEY_REDACTED]', text)
    return text

def truncate_snippet(text: str, max_chars: int = 1000) -> str:
    """Safely truncates response snippets while preserving relevant context."""
    if not text:
        return ""
    cleaned = sanitize_string(text)
    if len(cleaned) <= max_chars:
        return cleaned
    return cleaned[:max_chars] + f"\n... [Truncated: {len(cleaned) - max_chars} characters omitted]"
