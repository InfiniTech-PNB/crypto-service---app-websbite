# =============================================================================
# cbom_generator.py — CERT-IN CBOM Generator
# =============================================================================

from typing import Dict, Any, List
import uuid


# -----------------------------------------------------------------------------
# Algorithm metadata database
# -----------------------------------------------------------------------------

ALGORITHM_DB = {

    "AES_128_GCM": {
        "primitive": "AES",
        "mode": "GCM",
        "security_level": "128",
        "oid": "2.16.840.1.101.3.4.1.6"
    },

    "AES_256_GCM": {
        "primitive": "AES",
        "mode": "GCM",
        "security_level": "256",
        "oid": "2.16.840.1.101.3.4.1.46"
    },

    "ECDHE": {
        "primitive": "Elliptic Curve Diffie Hellman",
        "mode": None,
        "security_level": "128",
        "oid": "1.3.132.112"
    },

    "RSA": {
        "primitive": "RSA",
        "mode": None,
        "security_level": "112-128",
        "oid": "1.2.840.113549.1.1.1"
    },

    "MLKEM768": {
        "primitive": "Lattice KEM",
        "mode": None,
        "security_level": "NIST Level 3",
        "oid": "2.16.840.1.101.3.4.4.2"
    },

    "CHACHA20_POLY1305": {
        "primitive": "ChaCha20",
        "mode": "Poly1305",
        "security_level": "256",
        "oid": None
    },

    "X25519": {
        "primitive": "Elliptic Curve Diffie Hellman",
        "mode": None,
        "security_level": "128",
        "oid": "1.3.101.110"
    }
}


# -----------------------------------------------------------------------------
# Cipher suite parser
# -----------------------------------------------------------------------------
def parse_cipher_suite(cipher: str):

    """
    Supports both TLS 1.2 and TLS 1.3 cipher formats.
    """

    if not cipher:
        return None

    cipher = cipher.replace("TLS_", "")

    # TLS 1.3 format
    # Example: AES_128_GCM_SHA256
    if "_WITH_" not in cipher:

        parts = cipher.split("_")

        if len(parts) >= 3:

            cipher_algo = "_".join(parts[:3])

            return {
                "key_exchange": None,
                "authentication": None,
                "cipher": cipher_algo
            }

        return None

    # TLS 1.2 format
    parts = cipher.split("_WITH_")

    key_auth = parts[0].split("_")

    key_exchange = key_auth[0]

    authentication = key_auth[1] if len(key_auth) > 1 else None

    cipher_hash = parts[1].split("_")

    cipher_algo = "_".join(cipher_hash[:3])

    return {
        "key_exchange": key_exchange,
        "authentication": authentication,
        "cipher": cipher_algo
    }

# -----------------------------------------------------------------------------
# Algorithms section
# -----------------------------------------------------------------------------

def derive_algorithms(scan: Dict[str, Any]) -> List[Dict[str, Any]]:

    algorithms = []

    cipher = scan.get("cipher")

    parsed = parse_cipher_suite(cipher) if cipher else None

    if parsed:

        cipher_name = parsed["cipher"]

        if cipher_name in ALGORITHM_DB:

            meta = ALGORITHM_DB[cipher_name]

            algorithms.append({
                "name": cipher_name,
                "asset_type": "cipher",
                "primitive": meta["primitive"],
                "mode": meta["mode"],
                "classical_security_level": meta["security_level"],
                "oid": meta["oid"]
            })

        kex = parsed["key_exchange"]

        if kex in ALGORITHM_DB:

            meta = ALGORITHM_DB[kex]

            algorithms.append({
                "name": kex,
                "asset_type": "key_exchange",
                "primitive": meta["primitive"],
                "mode": meta["mode"],
                "classical_security_level": meta["security_level"],
                "oid": meta["oid"]
            })

    return algorithms


# -----------------------------------------------------------------------------
# Keys section
# -----------------------------------------------------------------------------

def derive_keys(scan: Dict[str, Any]):

    key_id = str(uuid.uuid4())

    return [{
        "name": scan.get("key_exchange"),
        "asset_type": "TLS Key",
        "id": key_id,
        "state": "active",
        "size": scan.get("key_size"),
        "creation_date": "unknown",
        "activation_date": "unknown"
    }]


# -----------------------------------------------------------------------------
# Protocols section
# -----------------------------------------------------------------------------

def derive_protocols(scan: Dict[str, Any]):

    return [{
        "name": "TLS",
        "version": scan.get("tls_version"),
        "cipher_suites": scan.get("cipher_suites"),
        "oid": None
    }]


# -----------------------------------------------------------------------------
# Certificates section
# -----------------------------------------------------------------------------

def derive_certificates(scan: Dict[str, Any]):

    return [{
        "name": scan.get("host"),
        "subject_name": scan.get("host"),
        "issuer_name": scan.get("issuer"),
        "validity_period": scan.get("expires"),
        "signature_algorithm_reference": scan.get("signature_algorithm"),
        "subject_public_key_reference": scan.get("key_size"),
        "certificate_format": "X509",
        "certificate_extension": None
    }]


# -----------------------------------------------------------------------------
# Main CBOM generator
# -----------------------------------------------------------------------------

def generate_cbom(scan_result: Dict[str, Any]):

    cbom = {

        "algorithms": derive_algorithms(scan_result),

        "keys": derive_keys(scan_result),

        "protocols": derive_protocols(scan_result),

        "certificates": derive_certificates(scan_result)
    }

    return cbom