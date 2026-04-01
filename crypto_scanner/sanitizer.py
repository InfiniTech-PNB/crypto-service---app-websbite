# =============================================================================
# sanitizer.py — Input Validation & Sanitization
# =============================================================================
# Validates and sanitizes user input before passing to subprocess commands.
# Prevents shell injection by rejecting dangerous characters.
# =============================================================================

import re
import logging
from typing import Optional
import ipaddress
logger = logging.getLogger("scanner")

# ---------------------------------------------------------------------------
# Hostname validation: RFC 952 / RFC 1123 compliant
# Only alphanumeric, hyphens, and dots allowed.
# ---------------------------------------------------------------------------
_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)

# IPv4 validation
_IPV4_RE = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)

# Characters that could enable shell injection
_DANGEROUS_CHARS = re.compile(r"[;&|`$(){}!<>\"\'\\\n\r\t]")

def validate_host(host: str) -> Optional[str]:
    if not host or not isinstance(host, str):
        logger.warning("[Sanitizer] Rejected empty or non-string host")
        return None

    host = host.strip().lower()

    if not host:
        logger.warning("[Sanitizer] Rejected whitespace-only host")
        return None

    # Check for shell-injection characters
    if _DANGEROUS_CHARS.search(host):
        logger.warning(
            "[Sanitizer] Rejected host with dangerous characters: %s", host
        )
        return None

    # ✅ NEW: Validate IP (IPv4 + IPv6)
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    # Validate as hostname
    if _HOSTNAME_RE.match(host):
        return host

    logger.warning("[Sanitizer] Rejected invalid host format: %s", host)
    return None
    
def validate_port(port: int) -> bool:
    """
    Validate a port number.

    Rules:
        - Must be an integer (not bool — bool is a subclass of int in Python)
        - Must be between 1 and 65535 inclusive

    Args:
        port: Port number to validate.

    Returns:
        True if valid, False otherwise.
    """
    # Reject booleans (bool is subclass of int in Python)
    if isinstance(port, bool):
        logger.warning("[Sanitizer] Rejected boolean as port: %s", port)
        return False

    if not isinstance(port, int):
        logger.warning("[Sanitizer] Rejected non-integer port: %s", port)
        return False

    if port < 1 or port > 65535:
        logger.warning("[Sanitizer] Rejected out-of-range port: %d", port)
        return False

    return True
