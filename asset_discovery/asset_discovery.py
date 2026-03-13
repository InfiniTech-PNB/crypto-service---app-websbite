# =============================================================================
# asset_discovery.py — Discovery Pipeline Orchestrator
# =============================================================================
# Orchestrates the full asset discovery pipeline:
#   1. Passive subdomain discovery (CT logs, Bufferover, ThreatCrowd)
#   2. Active DNS brute force
#   3. Hostname deduplication & normalization
#   4. Concurrent DNS resolution with IP validation
#   5. Per-IP port scanning with result reuse for duplicate IPs
#   6. Asset classification
#   7. Filter assets with ≥1 open service
#   8. Sort alphabetically by hostname
#
# Uses ThreadPoolExecutor (max_workers=20) for all concurrent operations.
# Individual host failures are logged and skipped — never crashes.
# =============================================================================

import logging
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from asset_discovery.discovery.ctlogs import (
    discover_from_ctlogs,
    discover_from_bufferover,
    discover_from_threatcrowd,
)
from asset_discovery.discovery.dns_brute import discover_from_dns
from asset_discovery.resolver import resolve_ip
from asset_discovery.scanner import scan_ports
from asset_discovery.classifier import classify_asset

logger = logging.getLogger("discovery")

# Maximum concurrent threads for resolution and scanning
MAX_WORKERS = 20


def discover_assets(domain: str) -> Dict[str, Any]:
    """
    Execute the full asset discovery pipeline for a given root domain.

    Pipeline stages:
        1. Run passive sources concurrently (crt.sh, Bufferover, ThreatCrowd)
        2. Run active DNS brute force
        3. Merge and deduplicate all discovered hostnames
        4. Resolve each hostname to IPv4 (concurrent, validated)
        5. Scan unique IPs for open ports (per-IP dedup)
        6. Classify each asset by subdomain and ports
        7. Filter out assets with no open services
        8. Sort results alphabetically by hostname

    Args:
        domain: Root domain to scan (e.g. "github.com").

    Returns:
        Dictionary matching the DiscoveryResult schema:
        {
            "domain": "example.com",
            "total_assets_found": N,
            "assets": [...]
        }
    """
    domain = domain.lower().strip().strip(".")

    logger.info("=" * 70)
    logger.info("[Discovery] Starting asset discovery for: %s", domain)
    logger.info("=" * 70)

    # -------------------------------------------------------------------------
    # Stage 1: Passive Subdomain Discovery (concurrent)
    # -------------------------------------------------------------------------
    logger.info("[Discovery] Stage 1: Passive subdomain discovery")

    ct_hosts: set = set()
    bufferover_hosts: set = set()
    threatcrowd_hosts: set = set()

    with ThreadPoolExecutor(max_workers=3) as executor:
        future_ct = executor.submit(discover_from_ctlogs, domain)
        future_bf = executor.submit(discover_from_bufferover, domain)
        future_tc = executor.submit(discover_from_threatcrowd, domain)

        try:
            ct_hosts = future_ct.result()
        except Exception as e:
            logger.error("[Discovery] CT logs source failed: %s", e)

        try:
            bufferover_hosts = future_bf.result()
        except Exception as e:
            logger.error("[Discovery] Bufferover source failed: %s", e)

        try:
            threatcrowd_hosts = future_tc.result()
        except Exception as e:
            logger.error("[Discovery] ThreatCrowd source failed: %s", e)

    # -------------------------------------------------------------------------
    # Stage 2: Active DNS Brute Force
    # -------------------------------------------------------------------------
    logger.info("[Discovery] Stage 2: DNS brute force")
    dns_hosts = discover_from_dns(domain, max_workers=MAX_WORKERS)

    # -------------------------------------------------------------------------
    # Stage 3: Merge and Deduplicate
    # -------------------------------------------------------------------------
    # Always include the root domain and www variant
    all_hosts = {domain, f"www.{domain}"}
    all_hosts |= ct_hosts
    all_hosts |= bufferover_hosts
    all_hosts |= threatcrowd_hosts
    all_hosts |= dns_hosts

    # Remove any remaining wildcard entries
    all_hosts = {h for h in all_hosts if not h.startswith("*")}

    logger.info("[Discovery] Total unique hosts after merge: %d", len(all_hosts))

    # -------------------------------------------------------------------------
    # Stage 4: DNS Resolution (concurrent)
    # -------------------------------------------------------------------------
    logger.info("[Discovery] Stage 4: Resolving hostnames to IPs")

    # host → ip mapping (only valid, globally-routable IPs)
    resolved: Dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_host = {
            executor.submit(resolve_ip, host): host for host in all_hosts
        }

        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                ip = future.result()
                if ip:
                    resolved[host] = ip
            except Exception as e:
                logger.debug("[Discovery] Resolution error for %s: %s", host, e)

    logger.info(
        "[Discovery] Resolved %d / %d hosts successfully",
        len(resolved),
        len(all_hosts),
    )

    # -------------------------------------------------------------------------
    # Stage 5: Port Scanning (per-IP dedup)
    # -------------------------------------------------------------------------
    logger.info("[Discovery] Stage 5: Scanning ports")

    # Build IP → [hosts] mapping to avoid scanning the same IP multiple times
    ip_to_hosts: Dict[str, List[str]] = {}
    for host, ip in resolved.items():
        ip_to_hosts.setdefault(ip, []).append(host)

    # Scan each unique IP concurrently
    ip_scan_results: Dict[str, List[Dict[str, object]]] = {}

    unique_ips = list(ip_to_hosts.keys())
    logger.info("[Discovery] Scanning %d unique IPs", len(unique_ips))

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_ip = {
            executor.submit(scan_ports, ip): ip for ip in unique_ips
        }

        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                services = future.result()
                ip_scan_results[ip] = services
            except Exception as e:
                logger.error("[Discovery] Port scan error for %s: %s", ip, e)
                ip_scan_results[ip] = []

    # -------------------------------------------------------------------------
    # Stage 6: Classification and Filtering
    # -------------------------------------------------------------------------
    logger.info("[Discovery] Stage 6: Classifying assets and filtering")

    assets: List[Dict[str, Any]] = []

    for host, ip in resolved.items():
        # Reuse scan results from the IP (dedup benefit)
        services = ip_scan_results.get(ip, [])

        # Only include hosts with at least one open service
        if not services:
            continue

        # Classify the asset
        asset_type = classify_asset(host, services)

        assets.append({
            "host": host,
            "ip": ip,
            "asset_type": asset_type,
            "services": [
                {"port": svc["port"], "protocol_name": svc["protocol_name"]}
                for svc in services
            ],
        })

    # -------------------------------------------------------------------------
    # Stage 7: Sort and Return
    # -------------------------------------------------------------------------
    assets.sort(key=lambda a: a["host"])

    result = {
        "domain": domain,
        "total_assets_found": len(assets),
        "assets": assets,
    }

    logger.info("=" * 70)
    logger.info(
        "[Discovery] Complete: %d assets found for %s",
        len(assets),
        domain,
    )
    logger.info("=" * 70)

    return result
