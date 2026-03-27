# =============================================================================
# crypto_scanner.py — Scan Orchestrator (Corrected)
# =============================================================================

import logging
from typing import Dict, List, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from crypto_scanner.sanitizer import validate_host, validate_port
from crypto_scanner.openssl_scanner import run_openssl_scan
from crypto_scanner.nmap_scanner import run_nmap_scan
from crypto_scanner.testssl_scanner import run_testssl_scan
from crypto_scanner.parser import parse_openssl_output, parse_nmap_output
from crypto_scanner.enricher import enrich_scan

logger = logging.getLogger("scanner")

MAX_WORKERS = 10


# -----------------------------------------------------------------------------
# Ports commonly running TLS
# -----------------------------------------------------------------------------

TLS_PORTS = {443, 465, 636, 993, 995, 8443, 990}

TLS_PROTOCOL_KEYWORDS = {
    "HTTPS",
    "SMTPS",
    "IMAPS",
    "POP3S",
    "FTPS",
    "TLS",
    "LDAPS",
    "SSL",
}


def is_tls_port(port: int, protocol_name: str) -> bool:

    if port in TLS_PORTS:
        return True

    upper = protocol_name.upper().replace("-", "")

    for keyword in TLS_PROTOCOL_KEYWORDS:
        if keyword in upper:
            return True

    return False


# -----------------------------------------------------------------------------
# Scan single target
# -----------------------------------------------------------------------------

def _scan_single_target(host: str, ip: str, port: int, scan_type: str) -> Dict[str, Any]:

    logger.info("[Scanner] Scanning %s (%s:%d) [%s]", host, ip, port, scan_type)

    # 1. Scanners step (raw execution only)
    openssl_res = run_openssl_scan(host, ip, port)
    classical_raw = openssl_res.get("classical_raw", "")
    oqs_raw = openssl_res.get("oqs_raw", "")
    error_msg = openssl_res.get("error_msg")

    nmap_raw = run_nmap_scan(ip, port)

    testssl_parsed: Dict[str, Any] = {}
    if scan_type == "deep":
        testssl_parsed = run_testssl_scan(host, ip, port)

    # 2. Parsers step (strict mapping only)
    classical_parsed = parse_openssl_output(classical_raw, error_msg=error_msg)
    oqs_parsed = parse_openssl_output(oqs_raw, error_msg=error_msg)
    nmap_parsed = parse_nmap_output(nmap_raw)

    # Log handshake failure if detected
    if classical_parsed.get("status") != "success":
         logger.warning("[Scanner] Handshake failed/blocked for %s — %s", host, classical_parsed.get("failure_reason"))

    # 3. Enricher step (infer, enrich, logic)
    enriched = enrich_scan(
        classical_parsed=classical_parsed,
        oqs_parsed=oqs_parsed,
        nmap_parsed=nmap_parsed,
        testssl_parsed=testssl_parsed,
        domain=host
    )

    return enriched


# -----------------------------------------------------------------------------
# Main scan function
# -----------------------------------------------------------------------------

def scan_assets(assets: List[Dict[str, Any]], scan_type: str = "soft") -> Dict[str, Any]:

    logger.info("=" * 70)
    logger.info("[Scanner] Starting crypto scan — %d assets", len(assets))
    logger.info("=" * 70)

    results: List[Dict[str, Any]] = []

    targets: List[Tuple[str, str, int, str]] = []
    unique_pairs: Dict[Tuple[str, int], str] = {}

    # --------------------------------------------------------------
    # Collect targets
    # --------------------------------------------------------------

    for asset in assets:

        host = validate_host(str(asset.get("host", "")))
        ip = validate_host(str(asset.get("ip", "")))

        if not host or not ip:
            continue

        for service in asset.get("services", []):

            port = service.get("port")
            protocol = service.get("protocol_name", "")

            if not validate_port(port):
                continue

            if not is_tls_port(port, protocol):
                continue

            targets.append((host, ip, port, protocol))

            pair = (ip, port)

            if pair not in unique_pairs:
                unique_pairs[pair] = host

    logger.info(
        "[Scanner] %d TLS targets, %d unique endpoints",
        len(targets),
        len(unique_pairs),
    )

    # --------------------------------------------------------------
    # Scan concurrently
    # --------------------------------------------------------------

    scan_cache: Dict[Tuple[str, int], Dict[str, Any]] = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:

        future_map = {}

        for (ip, port), host in unique_pairs.items():

            future = executor.submit(
                _scan_single_target,
                host,
                ip,
                port,
                scan_type,
            )

            future_map[future] = (ip, port)

        for future in as_completed(future_map):

            ip, port = future_map[future]

            try:
                scan_cache[(ip, port)] = future.result()

            except Exception as e:

                logger.error(
                    "[Scanner] Scan failed for %s:%d: %s",
                    ip,
                    port,
                    e,
                )

                scan_cache[(ip, port)] = {}

    # --------------------------------------------------------------
    # Assign results back to hosts
    # --------------------------------------------------------------

    for host, ip, port, protocol in targets:

        cached = scan_cache.get((ip, port), {})

        if not cached:
            continue

        # Add the routing identifying fields back to the result
        cached["host"] = host
        cached["ip"] = ip
        cached["port"] = port
        cached["protocol"] = protocol

        results.append(cached)

    logger.info("[Scanner] Complete: %d scan results", len(results))

    return {"results": results}