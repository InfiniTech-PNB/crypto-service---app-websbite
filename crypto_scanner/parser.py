# =============================================================================
# parser.py — Production TLS Scanner Parser (PQC Enabled)
# =============================================================================

import re
import logging
from datetime import datetime
from typing import Dict, Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger("scanner")


# =============================================================================
# Weak cipher patterns
# =============================================================================

WEAK_CIPHER_PATTERNS = [
    "RC4",
    "3DES",
    "DES",
    "NULL",
    "EXPORT",
    "anon",
    "MD5"
]


# =============================================================================
# PQC Algorithms
# =============================================================================

PQC_KEY_EXCHANGE = [

    # Kyber (older naming)
    "KYBER",
    "KYBER512",
    "KYBER768",
    "KYBER1024",

    # ML-KEM (NIST standardized Kyber)
    "MLKEM",
    "MLKEM512",
    "MLKEM768",
    "MLKEM1024",

    # Hybrid PQC TLS groups
    "X25519MLKEM",
    "X25519MLKEM512",
    "X25519MLKEM768",
    "X25519MLKEM1024",

    "SECP256R1MLKEM768",
    "SECP384R1MLKEM1024"
]


PQC_SIGNATURES = [

    "DILITHIUM",
    "DILITHIUM2",
    "DILITHIUM3",
    "DILITHIUM5",

    "FALCON",
    "FALCON512",
    "FALCON1024",

    "SPHINCS",
    "SPHINCS+"
]


# =============================================================================
# TLS / SSL normalization
# =============================================================================

_TLS_MAP = {

    "tlsv1": "TLSv1.0",
    "tlsv1.0": "TLSv1.0",
    "tls1.0": "TLSv1.0",

    "tlsv1.1": "TLSv1.1",
    "tls1.1": "TLSv1.1",

    "tlsv1.2": "TLSv1.2",
    "tls1.2": "TLSv1.2",

    "tlsv1.3": "TLSv1.3",
    "tls1.3": "TLSv1.3",

    "sslv2": "SSLv2",
    "ssl2": "SSLv2",

    "sslv3": "SSLv3",
    "ssl3": "SSLv3"
}


# =============================================================================
# Signature algorithm normalization
# =============================================================================

_SIG_MAP = {

    "sha256withrsaencryption": "RSA",
    "sha384withrsaencryption": "RSA",
    "sha512withrsaencryption": "RSA",

    "rsaencryption": "RSA",
    "rsa": "RSA",

    "ecdsa-with-sha256": "ECDSA",
    "ecdsa-with-sha384": "ECDSA",
    "ecdsa": "ECDSA",

    "ed25519": "Ed25519",
    "ed448": "Ed448"
}


# =============================================================================
# Helper functions
# =============================================================================

def normalize_tls(version: str) -> str:

    key = version.lower().replace(" ", "")
    return _TLS_MAP.get(key, version.strip())


def normalize_sig(sig: str) -> str:

    key = sig.lower()
    return _SIG_MAP.get(key, sig.strip())


def parse_date(raw: str) -> str:

    formats = [
        "%b %d %H:%M:%S %Y %Z",
        "%b  %d %H:%M:%S %Y %Z",
        "%b %d %H:%M:%S %Y"
    ]

    for f in formats:

        try:
            dt = datetime.strptime(raw.strip(), f)
            return dt.strftime("%Y-%m-%d")

        except Exception:
            pass

    return raw.strip()


def is_weak_cipher(cipher: str) -> bool:

    up = cipher.upper()

    for p in WEAK_CIPHER_PATTERNS:
        if p in up:
            return True

    return False


def has_pfs(cipher: str) -> bool:

    up = cipher.upper()

    if "ECDHE" in up:
        return True

    if "DHE" in up:
        return True

    return False


def extract_certificate_pem(raw: str):

    match = re.search(
        r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
        raw,
        re.S
    )

    if not match:
        return None

    return (
        "-----BEGIN CERTIFICATE-----"
        + match.group(1)
        + "-----END CERTIFICATE-----"
    )


def parse_certificate(pem: str):

    try:

        cert = x509.load_pem_x509_certificate(
            pem.encode(),
            default_backend()
        )

        public_key = cert.public_key()

        key_size = None

        if hasattr(public_key, "key_size"):
            key_size = public_key.key_size

        return {
            "issuer": cert.issuer.rfc4514_string(),
            "subject": cert.subject.rfc4514_string(),
            "not_before": cert.not_valid_before,
            "not_after": cert.not_valid_after,
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "key_size": key_size
        }

    except Exception as e:

        logger.warning("Certificate parsing failed: %s", e)

        return {}

# =============================================================================
# OpenSSL parser
# =============================================================================

def parse_openssl_output(raw: str) -> Dict[str, Any]:

    result = {
        "tls_version": None,
        "cipher": None,
        "issuer": None,
        "expires": None,
        "signature_algorithm": None,
        "key_size": None,
        "self_signed": False,
        "key_exchange": None,

        # PQC detection
        "pqc_key_exchange": None,
        "pqc_signature": None,
        "hybrid_pqc": False
    }

    if not raw:
        return result

    # --------------------------------------------------------------
    # Extract certificate information
    # --------------------------------------------------------------

    pem = extract_certificate_pem(raw)

    if pem:

        cert_info = parse_certificate(pem)

        if cert_info.get("issuer"):
            result["issuer"] = cert_info.get("issuer")

        if cert_info.get("not_after"):
            result["expires"] = str(cert_info.get("not_after"))

        if cert_info.get("signature_algorithm"):
            result["signature_algorithm"] = cert_info.get("signature_algorithm")

        if cert_info.get("key_size"):
            result["key_size"] = cert_info.get("key_size")


    raw_upper = raw.upper()

    # =============================================================================
    # PQC detection (GLOBAL SCAN)
    # =============================================================================

    for algo in PQC_KEY_EXCHANGE:

        if algo in raw_upper:

            result["pqc_key_exchange"] = algo

            if "MLKEM" in algo and (
                "X25519" in algo
                or "SECP" in algo
                or "P256" in algo
                or "P384" in algo
            ):
                result["hybrid_pqc"] = True
                result["key_exchange"] = "HYBRID_PQC"
            else:
                result["key_exchange"] = algo

            break

    for algo in PQC_SIGNATURES:

        if algo in raw_upper:
            result["pqc_signature"] = algo
            result["signature_algorithm"] = algo
            break


    # =============================================================================
    # TLS / SSL version
    # =============================================================================

    m = re.search(r"Protocol\s*:\s*((?:TLS|SSL)[^\s]+)", raw)

    if m:
        result["tls_version"] = normalize_tls(m.group(1))

    if result["tls_version"] is None:

        m = re.search(r"New,\s*((?:TLS|SSL)[^\s,]+)", raw)

        if m:
            result["tls_version"] = normalize_tls(m.group(1))


    # =============================================================================
    # Cipher
    # =============================================================================

    m = re.search(r"Cipher\s*:\s*(\S+)", raw)

    if m:

        cipher = m.group(1)

        if cipher not in ["0000", "(NONE)", "0"]:
            result["cipher"] = cipher

    if result["cipher"] is None:

        m = re.search(r"Cipher is\s+(\S+)", raw)

        if m:
            result["cipher"] = m.group(1)


    # =============================================================================
    # Classical key exchange detection
    # =============================================================================

    m = re.search(r"Server Temp Key:\s*(.+)", raw)

    if m:

        key = m.group(1).upper()

        if "X25519" in key and result["pqc_key_exchange"] is None:
            result["key_exchange"] = "X25519"

        elif "X448" in key and result["pqc_key_exchange"] is None:
            result["key_exchange"] = "X448"

        elif "ECDH" in key and result["pqc_key_exchange"] is None:
            result["key_exchange"] = "ECDHE"

        elif "DH" in key and result["pqc_key_exchange"] is None:
            result["key_exchange"] = "DHE"


    # =============================================================================
    # Key size
    # =============================================================================

    m = re.search(r"Server public key is (\d+) bit", raw)

    if m:
        result["key_size"] = int(m.group(1))

    if result["key_size"] is None:

        m = re.search(r"Public-Key:\s*\((\d+) bit\)", raw)

        if m:
            result["key_size"] = int(m.group(1))


    # =============================================================================
    # Issuer
    # =============================================================================

    m = re.search(r"issuer\s*[=:]\s*(.+)", raw, re.I)

    if m:

        issuer_raw = m.group(1)

        cn = re.search(r"CN\s*=\s*([^,/\n]+)", issuer_raw)

        if cn:
            result["issuer"] = cn.group(1).strip()

        else:
            result["issuer"] = issuer_raw.strip()[:100]


    # =============================================================================
    # Expiry
    # =============================================================================

    expires_match = re.search(r"NotAfter:\s*(.+?GMT)", raw)

    if not expires_match:
        expires_match = re.search(r"notAfter\s*=\s*(.+)", raw)

    if not expires_match:
        expires_match = re.search(r"Not\s+After\s*:\s*(.+)", raw)

    if expires_match:
        raw_date = expires_match.group(1).strip()
        result["expires"] = parse_date(raw_date)


    # =============================================================================
    # Signature
    # =============================================================================

    m = re.search(r"Signature Algorithm:\s*(\S+)", raw)

    if m:
        result["signature_algorithm"] = normalize_sig(m.group(1))

    if result["signature_algorithm"] is None:

        m = re.search(r"Peer signature type:\s*(\S+)", raw)

        if m:
            result["signature_algorithm"] = normalize_sig(m.group(1))


    # =============================================================================
    # Self signed
    # =============================================================================

    if "self signed" in raw.lower():
        result["self_signed"] = True


    return result

# =============================================================================
# Nmap parser
# =============================================================================

def parse_nmap_output(raw: str) -> Dict[str, Any]:

    result = {
        "tls_versions": [],
        "cipher_suites": [],
        "weak_ciphers": [],
        "key_exchange": None,
        "pfs_supported": False
    }

    if not raw:
        return result

    raw_upper = raw.upper()

    # TLS version detection
    for tls in ["TLSV1.0", "TLSV1.1", "TLSV1.2", "TLSV1.3", "SSLV3"]:
        if tls in raw_upper:
            result["tls_versions"].append(tls.replace("V", "v"))

    # Extract cipher suites
    cipher_matches = re.findall(r"TLS_[A-Z0-9_]+", raw_upper)

    for cipher in cipher_matches:

        if cipher not in result["cipher_suites"]:
            result["cipher_suites"].append(cipher)

        if is_weak_cipher(cipher):
            result["weak_ciphers"].append(cipher)

        if has_pfs(cipher):
            result["pfs_supported"] = True

    return result


# =============================================================================
# testssl.sh parser
# =============================================================================

def parse_testssl_json(data: Dict[str, Any]) -> Dict[str, Any]:

    result = {
        "tls_versions": [],
        "cipher_suites": [],
        "weak_ciphers": [],
        "key_exchange": None,
        "pfs_supported": False,
        "vulnerabilities": [],
        "issuer": None,
        "expires": None,
        "self_signed": False,
        "key_size": None,
        "certificate_algorithm": None
    }

    if not data:
        return result

    # TLS versions
    result["tls_versions"] = data.get("tls_versions", [])

    # Cipher suites
    result["cipher_suites"] = data.get("cipher_suites", [])

    # Weak ciphers
    for cipher in result["cipher_suites"]:
        if is_weak_cipher(cipher):
            result["weak_ciphers"].append(cipher)

    # PFS detection
    for cipher in result["cipher_suites"]:
        if has_pfs(cipher):
            result["pfs_supported"] = True
            break

    # Certificate information
    result["issuer"] = data.get("issuer")
    result["expires"] = data.get("expires")
    result["key_size"] = data.get("key_size")
    result["certificate_algorithm"] = data.get("certificate_algorithm")

    # Self-signed
    result["self_signed"] = data.get("self_signed", False)

    # Vulnerabilities
    result["vulnerabilities"] = data.get("vulnerabilities", [])

    return result