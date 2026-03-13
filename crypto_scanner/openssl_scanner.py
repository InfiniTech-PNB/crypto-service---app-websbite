# =============================================================================
# openssl_scanner.py — OpenSSL TLS Scanner (PQC + Classical Fallback)
# =============================================================================

import subprocess
import logging
from typing import Dict, Any

from crypto_scanner.parser import parse_openssl_output

logger = logging.getLogger("scanner")

OPENSSL_TIMEOUT = 15

# -----------------------------------------------------------------------------
# PQC hybrid groups (OpenSSL + OQS supported groups)
# -----------------------------------------------------------------------------

PQC_GROUPS = ":".join([
    "X25519MLKEM512",
    "X25519MLKEM768",
    "X25519MLKEM1024",
    "P256MLKEM512",
    "P384MLKEM768"
])


# -----------------------------------------------------------------------------
# Run OpenSSL command
# -----------------------------------------------------------------------------

def _run_openssl(cmd):

    process = subprocess.run(
        cmd,
        input=b"Q\n",
        capture_output=True,
        timeout=OPENSSL_TIMEOUT,
        shell=False
    )

    raw_output = ""

    if process.stdout:
        raw_output += process.stdout.decode("utf-8", errors="replace")

    if process.stderr:
        raw_output += process.stderr.decode("utf-8", errors="replace")

    return raw_output


# -----------------------------------------------------------------------------
# Detect PQC signatures inside raw output
# -----------------------------------------------------------------------------

def _detect_pqc_signatures(raw: str, result: Dict[str, Any]):

    lower = raw.lower()

    if "dilithium" in lower:
        result["pqc_signature"] = "Dilithium"

    elif "falcon" in lower:
        result["pqc_signature"] = "Falcon"

    elif "sphincs" in lower:
        result["pqc_signature"] = "SPHINCS+"

    return result


# -----------------------------------------------------------------------------
# Main scanner
# -----------------------------------------------------------------------------

def run_openssl_scan(host: str, ip: str, port: int) -> Dict[str, Any]:

    logger.info("[OpenSSL] Scanning %s (%s:%d)", host, ip, port)

    try:

        # ------------------------------------------------------------------
        # 1️⃣ PQC probe
        # ------------------------------------------------------------------

        pqc_cmd = [
            "openssl",
            "s_client",
            "-connect", f"{host}:{port}",
            "-servername", host,
            "-groups", PQC_GROUPS,
            "-showcerts"
        ]

        raw_output = _run_openssl(pqc_cmd)

        if raw_output:

            result = parse_openssl_output(raw_output)

            # Detect PQC signatures
            result = _detect_pqc_signatures(raw_output, result)

            # Accept PQC only if negotiated
            if "Server Temp Key:" in raw_output and result.get("pqc_key_exchange"):

                logger.info(
                    "[OpenSSL] PQC negotiated: %s",
                    result.get("pqc_key_exchange")
                )

                result["hybrid_pqc"] = True

                return result

        # ------------------------------------------------------------------
        # 2️⃣ Classical TLS fallback
        # ------------------------------------------------------------------

        logger.info("[OpenSSL] PQC not negotiated — running classical scan")

        normal_cmd = [
            "openssl",
            "s_client",
            "-connect", f"{host}:{port}",
            "-servername", host,
            "-showcerts"
        ]

        raw_output = _run_openssl(normal_cmd)

        if not raw_output.strip():

            logger.warning(
                "[OpenSSL] No output for %s:%d", ip, port
            )

            return _empty_result()

        logger.info("[OpenSSL RAW]\n%s", raw_output)

        result = parse_openssl_output(raw_output)

        # Detect PQC signatures even if key exchange isn't PQC
        result = _detect_pqc_signatures(raw_output, result)

        if result.get("pqc_signature"):
            result["hybrid_pqc"] = True

        logger.info(
            "[OpenSSL] %s:%d → TLS=%s Cipher=%s KeyEx=%s Sig=%s KeySize=%s",
            ip,
            port,
            result.get("tls_version"),
            result.get("cipher"),
            result.get("key_exchange"),
            result.get("signature_algorithm"),
            result.get("key_size")
        )

        return result

    except FileNotFoundError:

        logger.error(
            "[OpenSSL] openssl binary not found — install OpenSSL"
        )

        return _empty_result()

    except subprocess.TimeoutExpired:

        logger.warning(
            "[OpenSSL] Timeout (%ds) for %s:%d",
            OPENSSL_TIMEOUT,
            ip,
            port
        )

        return _empty_result()

    except Exception as e:

        logger.error(
            "[OpenSSL] Unexpected error for %s:%d: %s",
            ip,
            port,
            str(e)
        )

        return _empty_result()


# -----------------------------------------------------------------------------
# Empty result template
# -----------------------------------------------------------------------------

def _empty_result() -> Dict[str, Any]:

    return {
        "tls_version": None,
        "cipher": None,
        "issuer": None,
        "expires": None,
        "signature_algorithm": None,
        "key_size": None,
        "self_signed": False,
        "key_exchange": None,
        "pqc_key_exchange": None,
        "pqc_signature": None,
        "hybrid_pqc": False
    }