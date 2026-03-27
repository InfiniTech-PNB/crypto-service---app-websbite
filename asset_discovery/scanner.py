# =============================================================================
# scanner.py — Port and Service Discovery
# =============================================================================
# Scans a target IP for open ports relevant to cryptographic services.
# Uses raw socket connections with a 1-second timeout.
# Scans are performed per-IP (not per-host) to avoid duplicate work.
# =============================================================================

import socket
import logging
from typing import List, Dict

logger = logging.getLogger("discovery")

# ---------------------------------------------------------------------------
# Port → Protocol mapping for crypto-relevant services
# These are the ports where TLS/cryptography is typically in use.
# ---------------------------------------------------------------------------
CRYPTO_PORTS: Dict[int, str] = {
    22:   "SSH",
    80:   "HTTP",
    443:  "HTTPS",
    465:  "SMTPS",
    500:  "IPsec-VPN",
    636:  "LDAPS",
    993:  "IMAPS",
    995:  "POP3S",
    1194: "OpenVPN",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}


def scan_ports(ip: str, timeout: float = 2.0) -> List[Dict[str, object]]:
    """
    Scan a target IP for open crypto-relevant ports using TCP connect scan.

    For each port in CRYPTO_PORTS, attempts a TCP connection with the
    specified timeout. Only ports that accept the connection are returned.

    Args:
        ip: Target IPv4 address to scan.
        timeout: Socket connection timeout in seconds (default 1.0).

    Returns:
        List of dicts with "port" (int) and "protocol_name" (str) for
        each open port. Empty list if no ports are open.
    """
    open_services: List[Dict[str, object]] = []

    for port, protocol in CRYPTO_PORTS.items():
        try:
            # 🔥 Detect IP type (ADD THIS)
            ip_type = "IPv6" if ":" in ip else "IPv4"
            logger.debug("[Scanner] Scanning %s (%s)", ip, ip_type)

            # 🔥 Create correct socket (REPLACE THIS PART)
            if ":" in ip:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                address = (ip, port, 0, 0)  # IPv6 format
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                address = (ip, port)

            sock.settimeout(timeout)

            # 🔥 Use correct address
            result = sock.connect_ex(address)

            if result == 0:
                open_services.append({
                    "port": port,
                    "protocol_name": protocol,
                })
                logger.debug("[Scanner] %s:%d (%s) — OPEN", ip, port, protocol)
            else:
                logger.debug("[Scanner] %s:%d — closed", ip, port)

        except socket.timeout:
            logger.debug("[Scanner] %s:%d — timeout", ip, port)
        except OSError as e:
            logger.debug("[Scanner] %s:%d — error: %s", ip, port, e)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    logger.info(
        "[Scanner] %s — %d open port(s) found", ip, len(open_services)
    )
    return open_services
