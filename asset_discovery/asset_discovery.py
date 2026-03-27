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
import os
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from asset_discovery.discovery.ctlogs import (
    discover_from_ctlogs,
    discover_from_bufferover,
    discover_from_threatcrowd,
)

from asset_discovery.external_sources import (
    discover_from_virustotal,
    discover_from_otx,
    discover_from_wayback,
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
    # Stage 1: Passive + Fast Discovery
    # -------------------------------------------------------------------------
    logger.info("[Discovery] Stage 1: Passive (fast sources)")

    ct_hosts: set = set()
    bufferover_hosts: set = set()
    wayback_hosts: set = set()

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            "ct": executor.submit(discover_from_ctlogs, domain),
            "bufferover": executor.submit(discover_from_bufferover, domain),
            "wayback": executor.submit(discover_from_wayback, domain),
        }

        for name, future in futures.items():
            try:
                result = future.result(timeout=10)
                if name == "ct":
                    ct_hosts = result
                elif name == "bufferover":
                    bufferover_hosts = result
                elif name == "wayback":
                    wayback_hosts = result
            except Exception as e:
                logger.error("[Discovery] %s failed: %s", name, e)

    # -------------------------------------------------------------------------
    # Stage 2: Active DNS Brute Force
    # -------------------------------------------------------------------------
    logger.info("[Discovery] Stage 2: DNS brute force")
    dns_hosts = discover_from_dns(domain, max_workers=MAX_WORKERS)

    # -------------------------------------------------------------------------
    # Stage 3: Merge fast results
    # -------------------------------------------------------------------------
    all_hosts = {domain, f"www.{domain}"}
    all_hosts |= ct_hosts
    all_hosts |= bufferover_hosts
    all_hosts |= wayback_hosts
    all_hosts |= dns_hosts

    # Remove wildcards
    all_hosts = {h for h in all_hosts if not h.startswith("*")}

    logger.info("[Discovery] Hosts after fast stage: %d", len(all_hosts))

    # -------------------------------------------------------------------------
    # Stage 4: Conditional Enrichment (ONLY IF NEEDED)
    # -------------------------------------------------------------------------
    THRESHOLD = 50  # you can tune this

    if len(all_hosts) < THRESHOLD:
        logger.info("[Discovery] Low host count → running enrichment sources")

        vt_hosts: set = set()
        otx_hosts: set = set()

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                "vt": executor.submit(
                    discover_from_virustotal,
                    domain,
                    os.getenv("VT_API_KEY"),
                ),
                "otx": executor.submit(discover_from_otx, domain),
            }

            for name, future in futures.items():
                try:
                    result = future.result(timeout=20)
                    if name == "vt":
                        vt_hosts = result
                    elif name == "otx":
                        otx_hosts = result
                except Exception as e:
                    logger.error("[Discovery] %s failed: %s", name, e)

        all_hosts |= vt_hosts
        all_hosts |= otx_hosts

    logger.info("[Discovery] Total unique hosts after enrichment: %d", len(all_hosts))

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
                ips = future.result()
                if ips:
                    resolved.setdefault(host, []).extend(ips)
            except Exception as e:
                logger.debug("[Discovery] Resolution error for %s: %s", host, e)

    logger.info(
        "[Discovery] Resolved %d / %d hosts successfully",
        len(resolved),
        len(all_hosts),
    )

    # -------------------------------------------------------------------------
    # Stage 5: Port Scanning (optimized with CDN/IP limiting)
    # -------------------------------------------------------------------------
    logger.info("[Discovery] Stage 5: Scanning ports")

    MAX_IPS_PER_HOST = 2  # limit to avoid CDN explosion

    # -------------------------------------------------------------------------
    # Step 1: Build host → [ips] mapping
    # -------------------------------------------------------------------------
    host_to_ips: Dict[str, List[str]] = {}

    for host, ips in resolved.items():
        for ip in ips:
            host_to_ips.setdefault(host, []).append(ip)

    # -------------------------------------------------------------------------
    # Step 2: Limit IPs per host
    # -------------------------------------------------------------------------
    filtered_ips = set()

    for host, ips in host_to_ips.items():
        # Remove duplicates while preserving order
        seen = set()
        unique_host_ips = []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                unique_host_ips.append(ip)

        # Limit number of IPs per host
        limited_ips = unique_host_ips[:MAX_IPS_PER_HOST]
        filtered_ips.update(limited_ips)

    # -------------------------------------------------------------------------
    # Step 3: Prepare for scanning
    # -------------------------------------------------------------------------
    unique_ips = list(filtered_ips)

    logger.info(
        "[Discovery] Reduced IPs from %d → %d after CDN filtering",
        len(set(ip for ips in resolved.values() for ip in ips)),
        len(unique_ips),
    )

    logger.info("[Discovery] Scanning %d unique IPs", len(unique_ips))

    # -------------------------------------------------------------------------
    # Step 4: Scan IPs
    # -------------------------------------------------------------------------
    ip_scan_results: Dict[str, List[Dict[str, object]]] = {}

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

    for host, ips in resolved.items():
        for ip in ips:
            # 🔥 Skip IPs that were not scanned
            if ip not in ip_scan_results:
                continue

            services = ip_scan_results[ip]

            if not services:
                continue

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
