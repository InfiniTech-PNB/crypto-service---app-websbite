import socket
import logging
from typing import List, Dict

logger = logging.getLogger("discovery")

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
    Scan a target IP (IPv4 or IPv6) for open crypto-relevant ports.
    """

    open_services: List[Dict[str, object]] = []

    # ✅ Detect IP type ONCE
    is_ipv6 = ":" in ip
    ip_type = "IPv6" if is_ipv6 else "IPv4"

    logger.debug("[Scanner] Scanning %s (%s)", ip, ip_type)

    for port, protocol in CRYPTO_PORTS.items():
        try:
            # ✅ Create correct socket
            if is_ipv6:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                address = (ip, port, 0, 0)
                sock.settimeout(1.0)   # 🔥 faster timeout for IPv6
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                address = (ip, port)
                sock.settimeout(timeout)

            result = sock.connect_ex(address)

            if result == 0:
                open_services.append({
                    "port": port,
                    "protocol_name": protocol,
                })
                logger.debug("[Scanner] %s:%d (%s) — OPEN", ip, port, protocol)

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