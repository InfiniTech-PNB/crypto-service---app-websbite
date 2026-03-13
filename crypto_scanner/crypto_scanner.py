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
from crypto_scanner.parser import has_pfs

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

    openssl_result = run_openssl_scan(host, ip, port)

    nmap_result = run_nmap_scan(ip, port)

    testssl_result: Dict[str, Any] = {}

    if scan_type == "deep":
        testssl_result = run_testssl_scan(host, ip, port)

    merged = _merge_results(openssl_result, nmap_result, testssl_result)

    return merged


# -----------------------------------------------------------------------------
# Merge scan results
# -----------------------------------------------------------------------------

def _merge_results(
    openssl: Dict[str, Any],
    nmap: Dict[str, Any],
    testssl: Dict[str, Any],
) -> Dict[str, Any]:

    result: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Negotiated connection values (OpenSSL)
    # ------------------------------------------------------------------

    result["tls_version"] = openssl.get("tls_version")
    result["cipher"] = openssl.get("cipher")

    # ------------------------------------------------------------------
    # Supported TLS/SSL versions
    # ------------------------------------------------------------------

    tls_versions = set()

    if openssl.get("tls_version"):
        tls_versions.add(openssl["tls_version"])

    tls_versions.update(nmap.get("tls_versions", []))
    tls_versions.update(testssl.get("tls_versions", []))

    result["supported_tls_versions"] = sorted(tls_versions)

    # ------------------------------------------------------------------
    # Cipher suites
    # ------------------------------------------------------------------

    cipher_seen = set()
    cipher_list = []

    if openssl.get("cipher"):
        cipher_seen.add(openssl["cipher"])
        cipher_list.append(openssl["cipher"])

    for c in nmap.get("cipher_suites", []):
        if c not in cipher_seen:
            cipher_seen.add(c)
            cipher_list.append(c)

    for c in testssl.get("cipher_suites", []):
        if c not in cipher_seen:
            cipher_seen.add(c)
            cipher_list.append(c)

    result["cipher_suites"] = cipher_list

    # ------------------------------------------------------------------
    # Weak ciphers
    # ------------------------------------------------------------------

    weak_set = set()

    weak_set.update(nmap.get("weak_ciphers", []))
    weak_set.update(testssl.get("weak_ciphers", []))

    result["weak_ciphers"] = sorted(weak_set)

    # ------------------------------------------------------------------
    # Key exchange
    # ------------------------------------------------------------------

    result["key_exchange"] = (
        openssl.get("key_exchange")
        or testssl.get("key_exchange")
        or nmap.get("key_exchange")
    )

    # ------------------------------------------------------------------
    # PQC detection
    # ------------------------------------------------------------------

    result["pqc_key_exchange"] = openssl.get("pqc_key_exchange")
    result["pqc_signature"] = openssl.get("pqc_signature")
    result["hybrid_pqc"] = openssl.get("hybrid_pqc", False)

    # ------------------------------------------------------------------
    # Signature algorithm
    # ------------------------------------------------------------------

    result["signature_algorithm"] = (
        openssl.get("signature_algorithm")
        or testssl.get("certificate_algorithm")
    )

    # ------------------------------------------------------------------
    # Certificate key size
    # ------------------------------------------------------------------

    result["key_size"] = (
        openssl.get("key_size")
        or testssl.get("key_size")
    )

    # ------------------------------------------------------------------
    # Certificate issuer
    # ------------------------------------------------------------------

    result["issuer"] = (
        openssl.get("issuer")
        or testssl.get("issuer")
    )

    # ------------------------------------------------------------------
    # Certificate expiration
    # ------------------------------------------------------------------

    result["expires"] = (
        openssl.get("expires")
        or testssl.get("expires")
    )

    # ------------------------------------------------------------------
    # PFS detection
    # ------------------------------------------------------------------

    pfs = (
        testssl.get("pfs_supported", False)
        or nmap.get("pfs_supported", False)
    )

    if not pfs:
        for cipher in cipher_list:
            if has_pfs(cipher):
                pfs = True
                break

    result["pfs_supported"] = pfs

    # ------------------------------------------------------------------
    # Vulnerabilities
    # ------------------------------------------------------------------

    result["vulnerabilities"] = sorted(set(testssl.get("vulnerabilities", [])))

    # ------------------------------------------------------------------
    # Self signed certificate
    # ------------------------------------------------------------------

    result["self_signed"] = (
        openssl.get("self_signed", False)
        or testssl.get("self_signed", False)
    )

    return result


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

        results.append(
            {
                "host": host,
                "ip": ip,
                "port": port,
                "protocol": protocol,
                "tls_version": cached.get("tls_version"),
                "cipher": cached.get("cipher"),
                "key_exchange": cached.get("key_exchange"),
                "signature_algorithm": cached.get("signature_algorithm"),
                # PQC fields
                "pqc_key_exchange": cached.get("pqc_key_exchange"),
                "pqc_signature": cached.get("pqc_signature"),
                "hybrid_pqc": cached.get("hybrid_pqc", False),
                "supported_tls_versions": cached.get("supported_tls_versions", []),
                "cipher_suites": cached.get("cipher_suites", []),
                "weak_ciphers": cached.get("weak_ciphers", []),
                "key_size": cached.get("key_size"),
                "issuer": cached.get("issuer"),
                "expires": cached.get("expires"),
                "pfs_supported": cached.get("pfs_supported", False),
                "vulnerabilities": cached.get("vulnerabilities", []),
                "self_signed": cached.get("self_signed", False),
            }
        )

    logger.info("[Scanner] Complete: %d scan results", len(results))

    return {"results": results}