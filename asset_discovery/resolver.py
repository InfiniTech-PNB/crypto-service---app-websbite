# =============================================================================
# resolver.py — DNS Resolution with IP Validation
# =============================================================================
# Resolves hostnames to IPv4 addresses and validates that the IP is
# globally routable (not private, loopback, multicast, link-local, etc.).
# Uses socket for resolution and ipaddress module for validation.
# =============================================================================

import socket
import ipaddress
import logging
from typing import Optional

logger = logging.getLogger("discovery")


def resolve_ip(host: str) -> Optional[str]:
    """
    Resolve a hostname to its IPv4 address and validate it is globally routable.

    Rejection criteria (handled by ipaddress.is_global):
        - Private ranges (10.x, 172.16-31.x, 192.168.x)
        - Loopback (127.x.x.x)
        - Link-local (169.254.x.x)
        - Multicast (224.0.0.0 – 239.255.255.255)
        - Reserved / unspecified (0.0.0.0, 255.x.x.x)

    Args:
        host: Fully qualified hostname to resolve.

    Returns:
        The IPv4 address string if valid and globally routable, None otherwise.
    """
    try:
        # Use socket for fast resolution — returns the first A record
        ip_str = socket.gethostbyname(host)

        # Validate the resolved IP
        ip_obj = ipaddress.ip_address(ip_str)

        # Reject any IP that is not globally routable
        if not ip_obj.is_global:
            logger.debug(
                "[Resolver] %s → %s (rejected: non-global IP)", host, ip_str
            )
            return None

        logger.debug("[Resolver] %s → %s (valid)", host, ip_str)
        return ip_str

    except socket.gaierror:
        logger.debug("[Resolver] %s → DNS resolution failed", host)
        return None
    except socket.herror:
        logger.debug("[Resolver] %s → DNS host error", host)
        return None
    except socket.timeout:
        logger.debug("[Resolver] %s → DNS resolution timed out", host)
        return None
    except (ValueError, OSError) as e:
        logger.debug("[Resolver] %s → error: %s", host, e)
        return None
