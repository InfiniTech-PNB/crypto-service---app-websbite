# =============================================================================
# ctlogs.py — Passive Subdomain Discovery Sources
# =============================================================================
# Discovers subdomains using passive reconnaissance APIs:
#   1. Certificate Transparency logs (crt.sh)
#   2. Bufferover DNS records
#   3. ThreatCrowd domain reports
#
# All functions return set[str] of normalized hostnames.
# All API calls are wrapped in try/except — failures return empty sets.
# =============================================================================

import re
import time
import logging
import requests
from typing import Set

logger = logging.getLogger("discovery")

# ---------------------------------------------------------------------------
# Hostname validation regex — only valid FQDN characters
# ---------------------------------------------------------------------------
_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)


def _normalize_hostnames(raw_names: list[str], root_domain: str) -> Set[str]:
    """
    Normalize and filter a list of raw hostname strings.

    Steps:
        1. Strip whitespace and lowercase
        2. Split on newlines (crt.sh returns multi-line values)
        3. Remove wildcard prefixes (*.)
        4. Validate hostname format
        5. Only keep hostnames ending with the root domain
        6. Deduplicate via set

    Args:
        raw_names: List of raw hostname strings from any source.
        root_domain: The root domain to filter against (e.g. "github.com").

    Returns:
        A deduplicated set of valid, normalized hostnames.
    """
    normalized: Set[str] = set()
    root_lower = root_domain.lower().strip(".")

    for name in raw_names:
        if not name or not isinstance(name, str):
            continue

        # Split on newlines — crt.sh sometimes returns multi-line values
        parts = name.strip().split("\n")

        for part in parts:
            hostname = part.strip().lower()

            # Remove wildcard prefix
            if hostname.startswith("*."):
                hostname = hostname[2:]

            # Remove trailing dot
            hostname = hostname.rstrip(".")

            # Skip empty strings
            if not hostname:
                continue

            # Must end with root domain
            if not hostname.endswith(root_lower):
                continue

            # Validate hostname format
            if _HOSTNAME_RE.match(hostname):
                normalized.add(hostname)

    return normalized


# =============================================================================
# Source 1: Certificate Transparency Logs (crt.sh)
# =============================================================================

def discover_from_ctlogs(domain: str) -> Set[str]:
    """
    Query crt.sh Certificate Transparency logs for subdomains.

    Uses the crt.sh JSON API with deduplication enabled.
    Implements exponential backoff retry (3 attempts, 10s timeout).

    Args:
        domain: Root domain to search (e.g. "github.com").

    Returns:
        Set of normalized hostnames found in CT logs.
    """
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}

    raw_names: list[str] = []

    for attempt in range(1, 4):
        try:
            logger.info(
                "[Discovery] CT logs query attempt %d/3 for %s", attempt, domain
            )
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()

            data = response.json()

            # Extract all name values and common names
            for entry in data:
                name_value = entry.get("name_value", "")
                common_name = entry.get("common_name", "")
                if name_value:
                    raw_names.append(name_value)
                if common_name:
                    raw_names.append(common_name)

            break  # Success — exit retry loop

        except requests.exceptions.JSONDecodeError:
            logger.warning(
                "[Discovery] CT logs returned invalid JSON (attempt %d)", attempt
            )
        except requests.exceptions.Timeout:
            logger.warning(
                "[Discovery] CT logs request timed out (attempt %d)", attempt
            )
        except requests.exceptions.RequestException as e:
            logger.warning(
                "[Discovery] CT logs request failed (attempt %d): %s", attempt, e
            )

        # Exponential backoff: 2s, 4s before retrying
        if attempt < 3:
            backoff = 2 ** attempt
            logger.info("[Discovery] Retrying in %ds...", backoff)
            time.sleep(backoff)

    result = _normalize_hostnames(raw_names, domain)
    logger.info("[Discovery] CT logs found %d hosts", len(result))
    return result


# =============================================================================
# Source 2: Bufferover DNS Records
# =============================================================================

def discover_from_bufferover(domain: str) -> Set[str]:
    """
    Query Bufferover passive DNS API for subdomains.

    API: https://dns.bufferover.run/dns?q=.domain.com
    Response contains FDNS_A and RDNS fields with "hostname,IP" format.

    Args:
        domain: Root domain to search (e.g. "github.com").

    Returns:
        Set of normalized hostnames found via Bufferover.
    """
    url = f"https://dns.bufferover.run/dns?q=.{domain}"
    raw_names: list[str] = []

    try:
        logger.info("[Discovery] Querying Bufferover for %s", domain)
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()

        # Parse FDNS_A records — format: "IP,hostname" or "hostname,IP"
        for record in data.get("FDNS_A", []) or []:
            if isinstance(record, str) and "," in record:
                # Extract hostname — could be before or after comma
                parts = record.split(",")
                for part in parts:
                    part = part.strip()
                    # If it looks like a hostname (contains dots, no pure IP)
                    if "." in part and not _is_ip_like(part):
                        raw_names.append(part)

        # Parse RDNS records — same format
        for record in data.get("RDNS", []) or []:
            if isinstance(record, str) and "," in record:
                parts = record.split(",")
                for part in parts:
                    part = part.strip()
                    if "." in part and not _is_ip_like(part):
                        raw_names.append(part)

    except requests.exceptions.RequestException as e:
        logger.warning("[Discovery] Bufferover request failed: %s", e)
    except (ValueError, KeyError) as e:
        logger.warning("[Discovery] Bufferover response parsing failed: %s", e)

    result = _normalize_hostnames(raw_names, domain)
    logger.info("[Discovery] Bufferover found %d hosts", len(result))
    return result


def _is_ip_like(s: str) -> bool:
    """
    Quick check if a string looks like an IP address (digits and dots only).
    Used to separate hostnames from IPs in Bufferover records.
    """
    return all(c.isdigit() or c == "." for c in s)


# =============================================================================
# Source 3: ThreatCrowd Domain Report
# =============================================================================

def discover_from_threatcrowd(domain: str) -> Set[str]:
    """
    Query ThreatCrowd API for subdomains of the given domain.

    API: https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=example.com
    Response contains a "subdomains" list.

    Args:
        domain: Root domain to search (e.g. "github.com").

    Returns:
        Set of normalized hostnames found via ThreatCrowd.
    """
    url = "https://www.threatcrowd.org/searchApi/v2/domain/report/"
    params = {"domain": domain}
    raw_names: list[str] = []

    try:
        logger.info("[Discovery] Querying ThreatCrowd for %s", domain)
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()

        data = response.json()

        # Extract subdomains list
        subdomains = data.get("subdomains", [])
        if isinstance(subdomains, list):
            raw_names.extend(subdomains)

    except requests.exceptions.RequestException as e:
        logger.warning("[Discovery] ThreatCrowd request failed: %s", e)
    except (ValueError, KeyError) as e:
        logger.warning("[Discovery] ThreatCrowd response parsing failed: %s", e)

    result = _normalize_hostnames(raw_names, domain)
    logger.info("[Discovery] ThreatCrowd found %d hosts", len(result))
    return result
