# =============================================================================
# nmap_scanner.py — Nmap TLS Cipher Enumeration Scanner (Corrected)
# =============================================================================

import subprocess
import logging
from typing import Dict, Any

from crypto_scanner.parser import parse_nmap_output

logger = logging.getLogger("scanner")

NMAP_TIMEOUT = 30


def run_nmap_scan(ip: str, port: int) -> Dict[str, Any]:

    logger.info("[Nmap] Scanning %s:%d for TLS/SSL cipher suites", ip, port)

    try:

        cmd = [
            "nmap",
            "-p", str(port),
            "--script", "ssl-enum-ciphers",
            "--script-timeout", "20s",
            "-Pn",
            "-n",
            ip
        ]

        process = subprocess.run(
            cmd,
            capture_output=True,
            timeout=NMAP_TIMEOUT,
            shell=False
        )

        raw_output = ""

        if process.stdout:
            raw_output += process.stdout.decode("utf-8", errors="replace")

        if process.stderr:
            raw_output += process.stderr.decode("utf-8", errors="replace")

        if not raw_output.strip():

            logger.warning(
                "[Nmap] No output for %s:%d",
                ip,
                port
            )

            return _empty_result()

        logger.debug(
            "[Nmap] Raw output for %s:%d\n%s",
            ip,
            port,
            raw_output
        )

        result = parse_nmap_output(raw_output)

        logger.info(
            "[Nmap] %s:%d → Versions=%d Ciphers=%d Weak=%d",
            ip,
            port,
            len(result.get("tls_versions", [])),
            len(result.get("cipher_suites", [])),
            len(result.get("weak_ciphers", []))
        )

        return result

    except FileNotFoundError:

        logger.error(
            "[Nmap] nmap binary not found — install nmap"
        )

        return _empty_result()

    except subprocess.TimeoutExpired:

        logger.warning(
            "[Nmap] Timeout (%ds) for %s:%d",
            NMAP_TIMEOUT,
            ip,
            port
        )

        return _empty_result()

    except Exception as e:

        logger.error(
            "[Nmap] Unexpected error for %s:%d: %s",
            ip,
            port,
            str(e)
        )

        return _empty_result()


def _empty_result() -> Dict[str, Any]:

    return {
        "tls_versions": [],
        "cipher_suites": [],
        "weak_ciphers": [],
        "key_exchange": None,
        "pfs_supported": False,
    }