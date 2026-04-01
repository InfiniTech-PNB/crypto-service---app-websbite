import socket
import ipaddress
import logging
from typing import List

logger = logging.getLogger("discovery")


def resolve_ip(host: str) -> List[str]:
    """
    Resolve a hostname to ALL IPv4 + IPv6 addresses
    and return only globally routable ones.
    """

    valid_ips: List[str] = []
    seen = set()

    try:
        # Get IPv4
        _, _, ipv4_list = socket.gethostbyname_ex(host)

        # Get IPv6 (only)
        addr_info = socket.getaddrinfo(host, None)
        ipv6_list = []

        for info in addr_info:
            ip = info[4][0]
            if ":" in ip:  # only IPv6
                ipv6_list.append(ip)

        all_ips = ipv4_list + ipv6_list

        for ip_str in all_ips:
            try:
                ip_obj = ipaddress.ip_address(ip_str)

                if ip_obj.is_global and ip_str not in seen:
                    seen.add(ip_str)
                    valid_ips.append(ip_str)

            except ValueError:
                continue

        if valid_ips:
            logger.debug("[Resolver] %s → %s (valid)", host, valid_ips)

        return valid_ips

    except socket.gaierror:
        logger.debug("[Resolver] %s → DNS resolution failed", host)
    except socket.herror:
        logger.debug("[Resolver] %s → DNS host error", host)
    except socket.timeout:
        logger.debug("[Resolver] %s → DNS resolution timed out", host)
    except OSError as e:
        logger.debug("[Resolver] %s → error: %s", host, e)

    return []