# =============================================================================
# openssl_scanner.py — Correct PQC + Classical Scanner
# =============================================================================

import subprocess
import logging
from typing import Dict, Any

logger = logging.getLogger("scanner")

OPENSSL_TIMEOUT = 15


# -----------------------------------------------------------------------------
# Single scan (classical or PQC)
# -----------------------------------------------------------------------------

def _run_single_scan(host: str, port: int, use_oqs: bool, tls_flag: str = None):

    cmd = [
        "openssl",
        "s_client",
        "-connect", f"{host}:{port}",
        "-servername", host,
        "-showcerts",
        "-alpn", "h2,http/1.1",
        "-status"
    ]
    
    if tls_flag:
        cmd.append(tls_flag)

    # Enable OQS via environment (IMPORTANT)
    env = None
    if use_oqs:
        env = {"OPENSSL_CONF": "/etc/ssl/oqs.cnf"}  # adjust path if needed

    try:
        process = subprocess.run(
            cmd,
            input=b"Q\n",
            capture_output=True,
            timeout=OPENSSL_TIMEOUT,
            shell=False,
            env=env
        )

        raw_output = ""
        if process.stdout:
            raw_output += process.stdout.decode("utf-8", errors="replace")
        if process.stderr:
            raw_output += process.stderr.decode("utf-8", errors="replace")

        return raw_output, None

    except subprocess.TimeoutExpired:
        return "", "Connection timed out"
    except Exception as e:
        return "", str(e)


# -----------------------------------------------------------------------------
# Main function
# -----------------------------------------------------------------------------

def run_openssl_scan(host: str, ip: str, port: int) -> Dict[str, Any]:

    logger.info("[OpenSSL] Scanning %s (%s:%d)", host, ip, port)

    try:
        # -----------------------------
        # 1. Classical scan (Default)
        # -----------------------------
        classical_raw, error = _run_single_scan(host, port, use_oqs=False)

        # -----------------------------
        # 2. Fallback to TLS 1.2?
        # -----------------------------
        # If handshake fails (detect (NONE) or empty output with no error)
        if not classical_raw or "Cipher is (NONE)" in classical_raw or "handshake failure" in (classical_raw or "").lower():
            logger.info("[OpenSSL] Handshake failed or (NONE) cipher for %s. Retrying with TLS 1.2...", host)
            classical_raw_f2, error_f2 = _run_single_scan(host, port, use_oqs=False, tls_flag="-tls1_2")
            
            # If fallback produced something better, use it
            if classical_raw_f2 and "Cipher is (NONE)" not in classical_raw_f2:
                classical_raw = classical_raw_f2
                error = error_f2

        # -----------------------------
        # 3. PQC scan (OQS enabled)
        # -----------------------------
        pqc_raw, _ = _run_single_scan(host, port, use_oqs=True)

        return {
            "classical_raw": classical_raw,
            "oqs_raw": pqc_raw,
            "error_msg": error
        }

    except Exception as e:
        logger.error("[OpenSSL] Error for %s:%d: %s", ip, port, str(e))
        return {
            "classical_raw": "",
            "oqs_raw": "",
            "error_msg": str(e)
        }