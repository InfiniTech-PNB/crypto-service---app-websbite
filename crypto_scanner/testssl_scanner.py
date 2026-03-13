# =============================================================================
# testssl_scanner.py — testssl.sh Deep Scanner
# =============================================================================
# Runs testssl.sh for comprehensive TLS analysis during "deep" scans.
# Outputs JSON to a temp file, parses it, and cleans up.
# Only invoked when scan_type == "deep".
# =============================================================================

import os
import json
import subprocess
import logging
from typing import Dict, Any

from crypto_scanner.parser import parse_testssl_json

logger = logging.getLogger("scanner")

# Command timeout in seconds (testssl is slow)
TESTSSL_TIMEOUT = 300

# Path to testssl.sh — relative to project root
TESTSSL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "testssl.sh", "testssl.sh"
)


def run_testssl_scan(host: str, ip: str, port: int) -> Dict[str, Any]:
    """
    Run testssl.sh for comprehensive TLS vulnerability analysis.

    Command:
        ./testssl.sh --jsonfile-pretty <output_file> {host}:{port}

    The JSON output is written to /tmp/testssl_{ip}_{port}.json,
    parsed, and then cleaned up.

    Args:
        host: Target hostname.
        ip: Target IPv4 address.
        port: Target TCP port.

    Returns:
        Parsed dictionary with protocols, vulnerabilities, ciphers,
        certificate info, and PFS support. Empty result on failure.
    """
    # Build unique output filename
    safe_ip = ip.replace(".", "_")
    json_output = os.path.join(
        os.environ.get("TEMP", "/tmp"),
        f"testssl_{safe_ip}_{port}.json",
    )

    logger.info("[testssl] Deep scanning %s (%s:%d)", host, ip, port)

    try:
        # Check if testssl.sh exists
        if not os.path.isfile(TESTSSL_PATH):
            logger.error(
                "[testssl] testssl.sh not found at %s", TESTSSL_PATH
            )
            return _empty_result()

        cmd = [
            TESTSSL_PATH,
            "--jsonfile-pretty", json_output,
            f"{host}:{port}",
        ]

        process = subprocess.run(
            cmd,
            capture_output=True,
            timeout=TESTSSL_TIMEOUT,
            shell=False,
        )

        # Log any warnings from testssl
        if process.stderr:
            stderr = process.stderr.decode("utf-8", errors="replace")
            if stderr.strip():
                logger.debug("[testssl] stderr: %s", stderr[:500])

        # Parse the JSON output file
        if not os.path.isfile(json_output):
            logger.warning(
                "[testssl] JSON output file not created for %s:%d",
                ip, port,
            )
            return _empty_result()

        with open(json_output, "r", encoding="utf-8") as f:
            data = json.load(f)

        result = parse_testssl_json(data)
        logger.info(
            "[testssl] %s:%d → %d TLS versions, %d vulns",
            ip, port,
            len(result.get("tls_versions", [])),
            len(result.get("vulnerabilities", [])),
        )
        return result

    except FileNotFoundError:
        logger.error("[testssl] testssl.sh binary not found")
        return _empty_result()
    except subprocess.TimeoutExpired:
        logger.warning(
            "[testssl] Timeout after %ds for %s:%d",
            TESTSSL_TIMEOUT, ip, port,
        )
        return _empty_result()
    except json.JSONDecodeError as e:
        logger.error(
            "[testssl] Failed to parse JSON output for %s:%d: %s",
            ip, port, e,
        )
        return _empty_result()
    except Exception as e:
        logger.error(
            "[testssl] Unexpected error for %s:%d: %s", ip, port, e
        )
        return _empty_result()
    finally:
        # Cleanup the temporary JSON file
        try:
            if os.path.isfile(json_output):
                os.remove(json_output)
                logger.debug("[testssl] Cleaned up %s", json_output)
        except OSError:
            pass


def _empty_result() -> Dict[str, Any]:
    """Return an empty testssl result dictionary."""
    return {
        "tls_versions": [],
        "cipher_suites": [],
        "weak_ciphers": [],
        "key_exchange": None,
        "key_size": None,
        "certificate_algorithm": None,
        "issuer": None,
        "expires": None,
        "pfs_supported": False,
        "vulnerabilities": [],
        "self_signed": False,
    }
