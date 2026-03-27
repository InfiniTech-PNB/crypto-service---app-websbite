# =============================================================================
# cbom_generator.py — FINAL FRONTEND-READY VERSION
# =============================================================================

from typing import Dict, Any, List
import uuid


# -----------------------------------------------------------------------------
# Algorithm metadata
# -----------------------------------------------------------------------------

ALGORITHM_DB = {
    "AES_128_GCM": {"primitive": "AES", "mode": "GCM", "security_level": "128"},
    "AES_256_GCM": {"primitive": "AES", "mode": "GCM", "security_level": "256"},
    "CHACHA20_POLY1305": {"primitive": "ChaCha20", "mode": "Poly1305", "security_level": "256"},
    "X25519": {"primitive": "Elliptic Curve Diffie Hellman", "mode": None, "security_level": "128"},
    "RSA": {"primitive": "RSA", "mode": None, "security_level": "112-128"},
    "ECDSA": {"primitive": "Elliptic Curve Digital Signature Algorithm", "mode": None, "security_level": "128"},
}


# -----------------------------------------------------------------------------
# Cipher parser
# -----------------------------------------------------------------------------

def parse_cipher(cipher: str):
    if not cipher:
        return None

    if "AES_256_GCM" in cipher:
        return "AES_256_GCM"
    if "AES_128_GCM" in cipher:
        return "AES_128_GCM"
    if "CHACHA20_POLY1305" in cipher:
        return "CHACHA20_POLY1305"

    return None


# -----------------------------------------------------------------------------
# Algorithms
# -----------------------------------------------------------------------------

def derive_algorithms(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    negotiated = scan.get("negotiated", {})
    cert = scan.get("certificate", {})

    algorithms = []
    seen = set()

    def add(name, asset_type):
        if not name or name in seen:
            return

        meta = ALGORITHM_DB.get(name, {
            "primitive": "Unknown",
            "mode": None,
            "security_level": "Unknown"
        })

        algorithms.append({
            "name": name,
            "asset_type": asset_type,
            "primitive": meta["primitive"],
            "mode": meta["mode"],
            "classical_security_level": meta["security_level"],
            "oid": None
        })

        seen.add(name)

    add(parse_cipher(negotiated.get("cipher")), "cipher")
    add(negotiated.get("key_exchange"), "key_exchange")
    add(cert.get("signature_algorithm"), "signature")

    return algorithms


# -----------------------------------------------------------------------------
# Keys (DEDUP FRIENDLY)
# -----------------------------------------------------------------------------

def derive_keys(scan: Dict[str, Any]):
    negotiated = scan.get("negotiated", {})
    cert = scan.get("certificate", {})

    keys = []

    # Stable ID instead of UUID
    kex_name = negotiated.get("key_exchange")
    kex_size = negotiated.get("server_temp_key_size")
    kex_id = f"{kex_name}-{kex_size}"

    keys.append({
        "name": kex_name,
        "asset_type": "ephemeral_key",
        "id": kex_id,
        "state": "active",
        "size": kex_size,
        "creation_date": "unknown",
        "activation_date": "unknown"
    })

    pub = cert.get("public_key", {})
    pub_type = pub.get("type")
    pub_size = pub.get("size")

    pub_id = f"{pub_type}-{pub_size}"

    keys.append({
        "name": f"{pub_type} Public Key",
        "asset_type": "public_key",
        "id": pub_id,
        "state": "active",
        "size": pub_size,
        "creation_date": cert.get("not_before"),
        "activation_date": cert.get("not_before")
    })

    return keys, pub_id


# -----------------------------------------------------------------------------
# Protocols
# -----------------------------------------------------------------------------

def derive_protocols(scan: Dict[str, Any]):
    negotiated = scan.get("negotiated", {})

    return [{
        "name": "TLS",
        "version": negotiated.get("tls_version"),
        "cipher_suites": [negotiated.get("cipher")],
        "alpn": negotiated.get("alpn"),
        "oid": None
    }]


# -----------------------------------------------------------------------------
# Certificates (STRUCTURED)
# -----------------------------------------------------------------------------

def derive_certificates(scan: Dict[str, Any], pub_key_id: str):
    cert = scan.get("certificate", {})

    leaf = {
        "subject_name": cert.get("subject"),
        "issuer_name": cert.get("issuer"),
        "validity_period": {
            "not_before": cert.get("not_before"),
            "not_after": cert.get("expires")
        },
        "signature_algorithm_reference": cert.get("signature_algorithm"),
        "subject_public_key_reference": pub_key_id,
        "certificate_format": "X509",
        "certificate_extension": cert.get("extensions"),
        "certificate_history": cert.get("certificate_history", []),
        "fingerprint_sha256": cert.get("fingerprint_sha256")
    }

    chain = []
    for c in cert.get("certificate_chain", []):
        chain.append({
            "subject": c.get("subject"),
            "issuer": c.get("issuer"),
            "fingerprint_sha256": c.get("fingerprint_sha256"),
            "is_chain_certificate": True
        })

    return {
        "leaf": leaf,
        "chain": chain
    }


# -----------------------------------------------------------------------------
# MAIN GENERATOR
# -----------------------------------------------------------------------------

def generate_cbom(scan_results: Dict[str, Any], mode: str = "per_asset"):

    results = scan_results.get("results", [scan_results])

    # ---------------- PER ASSET ----------------

    if mode == "per_asset":
        cboms = []
        failed_assets = []

        for res in results:
            if hasattr(res, "model_dump"):
                res = res.model_dump()

            if res.get("status") != "success":
                failed_assets.append({
                    "host": res.get("host"),
                    "reason": res.get("failure_reason")
                })
                continue

            keys, pub_id = derive_keys(res)
            certs = derive_certificates(res, pub_id)

            cboms.append({
                "asset": res.get("host"),
                "algorithms": derive_algorithms(res),
                "keys": keys,
                "protocols": derive_protocols(res),
                "certificates": [
                    {
                        "asset": res.get("host"),
                        "leaf_certificate": certs["leaf"],
                        "certificate_chain": certs["chain"]
                    }
                ]
            })

        return {
            "assets": cboms,
            "failed_assets": failed_assets
        }

    # ---------------- AGGREGATE ----------------

    agg = {
        "assets": [],
        "algorithms": [],
        "keys": [],
        "protocols": [],
        "certificates": [],
        "failed_assets": []
    }

    seen_algo = set()
    seen_proto = set()
    seen_keys = set()

    for res in results:
        if hasattr(res, "model_dump"):
            res = res.model_dump()

        if res.get("status") != "success":
            agg["failed_assets"].append({
                "host": res.get("host"),
                "reason": res.get("failure_reason")
            })
            continue

        agg["assets"].append(res.get("host"))

        keys, pub_id = derive_keys(res)
        certs = derive_certificates(res, pub_id)

        # Algorithms
        for a in derive_algorithms(res):
            if a["name"] not in seen_algo:
                agg["algorithms"].append(a)
                seen_algo.add(a["name"])

        # Keys (DEDUP)
        for k in keys:
            if k["id"] not in seen_keys:
                agg["keys"].append(k)
                seen_keys.add(k["id"])

        # Protocols
        for p in derive_protocols(res):
            key = (p["version"], p["cipher_suites"][0], p["alpn"])
            if key not in seen_proto:
                agg["protocols"].append(p)
                seen_proto.add(key)

        # Certificates (GROUPED PER ASSET)
        agg["certificates"].append({
            "asset": res.get("host"),
            "leaf_certificate": certs["leaf"],
            "certificate_chain": certs["chain"]
        })

    return agg