import logging
import re
import sys
from typing import Optional

# Sensitive patterns to scrub from all log outputs
SENSITIVE_PATTERNS = [
    re.compile(r'(?i)(password|passwd|secret|api[_-]?key|token|auth|bearer)\s*[:=]\s*["\']?([^"\'\s&]+)', re.IGNORECASE),
    re.compile(r'(?i)(bearer\s+)([a-zA-Z0-9_\-\.]{15,})'),
    re.compile(r'(?i)(cookie:\s*)([^\r\n]+)'),
]

class RedactingFormatter(logging.Formatter):
    """Logging formatter that scrubs API keys, bearer tokens, passwords, and cookies."""
    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        for pattern in SENSITIVE_PATTERNS:
            msg = pattern.sub(r'\1: [REDACTED]', msg)
        return msg

def get_logger(name: str = "aegis.vuln_scanner", level: int = logging.INFO) -> logging.Logger:
    """Configures and returns a structured logger with security redactions."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = RedactingFormatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(level)
    return logger

logger = get_logger()
