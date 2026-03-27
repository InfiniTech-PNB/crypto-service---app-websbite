# =============================================================================
# external_sources.py — Passive Enrichment Sources
# =============================================================================
# Additional passive sources used for enrichment (Stage 2):
#   1. VirusTotal (rate-limited)
#   2. AlienVault OTX
#   3. Wayback Machine (historical URLs)
#
# All functions return set[str] of normalized hostnames.
# Failures return empty sets.
# =============================================================================

import re
import time
import logging
import requests
from typing import Set
from dotenv import load_dotenv
import os

load_dotenv()

api_key = os.getenv("API_KEY")
logger = logging.getLogger("discovery")

# Reuse same hostname validation philosophy as ctlogs.py
_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)


# -----------------------------------------------------------------------------
# Shared normalization (same behavior as ctlogs)
# -----------------------------------------------------------------------------
def _normalize_hostnames(raw_names: list[str], root_domain: str) -> Set[str]:
    normalized: Set[str] = set()
    root_lower = root_domain.lower().strip(".")

    for name in raw_names:
        if not name or not isinstance(name, str):
            continue

        hostname = name.strip().lower()

        # Remove wildcard
        if hostname.startswith("*."):
            hostname = hostname[2:]

        # Remove trailing dot
        hostname = hostname.rstrip(".")

        if not hostname:
            continue

        if not hostname.endswith(root_lower):
            continue

        if _HOSTNAME_RE.match(hostname):
            normalized.add(hostname)

    return normalized


# =============================================================================
# 1. VirusTotal
# =============================================================================
def discover_from_virustotal(domain: str, api_key: str | None) -> Set[str]:
    """
    Query VirusTotal for subdomains.

    Rate limit: 4 req/min → enforced via sleep.

    Args:
        domain: Root domain
        api_key: VirusTotal API key

    Returns:
        Set of normalized hostnames
    """
    if not api_key:
        logger.warning("[Discovery] VirusTotal API key missing")
        return set()

    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": api_key}

    raw_names: list[str] = []

    try:
        logger.info("[Discovery] Querying VirusTotal for %s", domain)

        # Respect rate limits
        time.sleep(16)

        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        data = response.json()

        for item in data.get("data", []):
            host = item.get("id", "")
            if host:
                raw_names.append(host)

    except requests.exceptions.RequestException as e:
        logger.warning("[Discovery] VirusTotal request failed: %s", e)
    except (ValueError, KeyError) as e:
        logger.warning("[Discovery] VirusTotal parsing failed: %s", e)

    result = _normalize_hostnames(raw_names, domain)
    logger.info("[Discovery] VirusTotal found %d hosts", len(result))
    return result


# =============================================================================
# 2. AlienVault OTX
# =============================================================================
def discover_from_otx(domain: str) -> Set[str]:
    """
    Query AlienVault OTX passive DNS.

    Args:
        domain: Root domain

    Returns:
        Set of normalized hostnames
    """
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

    raw_names: list[str] = []

    try:
        logger.info("[Discovery] Querying OTX for %s", domain)

        response = requests.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()

        for entry in data.get("passive_dns", []):
            host = entry.get("hostname", "")
            if host:
                raw_names.append(host)

    except requests.exceptions.RequestException as e:
        logger.warning("[Discovery] OTX request failed: %s", e)
    except (ValueError, KeyError) as e:
        logger.warning("[Discovery] OTX parsing failed: %s", e)

    result = _normalize_hostnames(raw_names, domain)
    logger.info("[Discovery] OTX found %d hosts", len(result))
    return result


# =============================================================================
# 3. Wayback Machine
# =============================================================================
def discover_from_wayback(domain: str) -> Set[str]:
    """
    Extract subdomains from Wayback Machine archived URLs.

    Args:
        domain: Root domain

    Returns:
        Set of normalized hostnames
    """
    url = (
        f"http://web.archive.org/cdx/search/cdx?"
        f"url=*.{domain}&output=json&fl=original&collapse=urlkey"
    )

    raw_names: list[str] = []

    try:
        logger.info("[Discovery] Querying Wayback Machine for %s", domain)

        response = requests.get(url, timeout=20)
        response.raise_for_status()
        data = response.json()

        # Skip header row
        for row in data[1:]:
            full_url = row[0]

            matches = re.findall(r"https?://([^/]+)/?", full_url)
            raw_names.extend(matches)

    except requests.exceptions.RequestException as e:
        logger.warning("[Discovery] Wayback request failed: %s", e)
    except (ValueError, KeyError) as e:
        logger.warning("[Discovery] Wayback parsing failed: %s", e)

    result = _normalize_hostnames(raw_names, domain)
    logger.info("[Discovery] Wayback found %d hosts", len(result))
    return result