# =============================================================================
# enricher.py — FINAL CORRECT VERSION (Production Ready)
# =============================================================================

import logging
import requests
import json
from typing import Dict, Any, List
from datetime import datetime
import ssl
import socket

logger = logging.getLogger("enricher")

# =============================================================================
# Certificate history (FULLY FREE ARCHITECTURE)
# crt.sh + base-domain fallback + live TLS fallback
# =============================================================================
_CERT_HISTORY_CACHE: Dict[str, List[Dict[str, str]]] = {}
def get_certificate_history(domain: str) -> List[Dict[str, str]]:

    if not domain:
        return []

    if domain.replace(".", "").isdigit():
        return []

    if domain in _CERT_HISTORY_CACHE:
        return _CERT_HISTORY_CACHE[domain]

    # =========================================================
    # Helper: Normalize (DO NOT CHANGE OUTPUT FORMAT)
    # =========================================================
    def normalize(entries):
        unique = {}

        for e in entries:
            try:
                issuer = e.get("issuer", "Unknown")

                nb = datetime.strptime(e["not_before"], "%Y-%m-%d")
                na = datetime.strptime(e["not_after"], "%Y-%m-%d")

                key = f"{issuer}|{nb.strftime('%Y-%m-%d')}"

                if key not in unique:
                    unique[key] = {
                        "issuer": issuer,
                        "not_before": nb.strftime("%Y-%m-%d"),
                        "not_after": na.strftime("%Y-%m-%d"),
                        "date_obj": nb
                    }
            except:
                continue

        sorted_certs = sorted(unique.values(), key=lambda x: x["date_obj"], reverse=True)

        return [
            {
                "issuer": c["issuer"],
                "not_before": c["not_before"],
                "not_after": c["not_after"]
            }
            for c in sorted_certs[:5]
        ]

    # =========================================================
    # 🥇 1. CRT.SH (PRIMARY - IMPROVED)
    # =========================================================
    def fetch_crtsh(query):
        try:
            url = f"https://crt.sh/?q={query}&output=json"
            r = requests.get(url, timeout=20)

            if r.status_code != 200:
                return []

            text = r.text.strip()
            if not text:
                return []

            if text.startswith("["):
                data = json.loads(text)
            else:
                data = json.loads(f"[{text.replace('}{', '},{')}]")

            return data if isinstance(data, list) else []

        except Exception as e:
            logger.warning(f"[crt.sh] failed for {query}: {e}")
            return []

    try:
        logger.info(f"[cert-history] crt.sh wildcard for {domain}")

        # Always use wildcard first (better coverage)
        data = fetch_crtsh(f"%.{domain}")

        # fallback: exact domain
        if not data:
            data = fetch_crtsh(domain)

        # fallback: base domain (VERY IMPORTANT)
        if not data:
            parts = domain.split(".")
            if len(parts) > 2:
                base = ".".join(parts[-2:])
                data = fetch_crtsh(f"%.{base}")

        entries = []

        for entry in data:
            issuer_raw = entry.get("issuer_name", "")
            issuer = issuer_raw.split("O=")[-1].split(",")[0] if "O=" in issuer_raw else issuer_raw

            entries.append({
                "issuer": issuer,
                "not_before": entry.get("not_before", "")[:10],
                "not_after": entry.get("not_after", "")[:10]
            })

        if entries:
            result = normalize(entries)
            _CERT_HISTORY_CACHE[domain] = result
            return result

    except Exception as e:
        logger.warning(f"[cert-history] crt.sh stage failed: {e}")

    # =========================================================
    # 🥈 2. LIVE TLS FETCH (FINAL FALLBACK - GUARANTEED)
    # =========================================================
    try:
        logger.info(f"[cert-history] Live TLS fallback for {domain}")

        ctx = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        issuer = dict(x[0] for x in cert.get("issuer", []))
        issuer_name = issuer.get("organizationName", "Unknown")

        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").strftime("%Y-%m-%d")
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").strftime("%Y-%m-%d")

        result = [{
            "issuer": issuer_name,
            "not_before": not_before,
            "not_after": not_after
        }]

        _CERT_HISTORY_CACHE[domain] = result
        return result

    except Exception as e:
        logger.warning(f"[cert-history] TLS fallback failed: {e}")

    # =========================================================
    # ❌ ALL FAILED
    # =========================================================
    _CERT_HISTORY_CACHE[domain] = []
    return []

# =============================================================================
# PQC Detection (CORRECT)
# =============================================================================

def extract_pqc_group(temp_key: str | None) -> str | None:
    if not temp_key:
        return None

    g = temp_key.upper()

    if any(x in g for x in ["KYBER", "MLKEM", "FRODO", "BIKE", "HQC"]):
        return g.strip()

    return None


def classify_pqc(group: str) -> str:
    g = group.upper()

    if any(x in g for x in ["KYBER", "MLKEM", "FRODO", "BIKE", "HQC"]):
        if any(x in g for x in ["X25519", "SECP", "P-256", "P-384"]):
            return "hybrid"
        return "pure"

    return "unknown"


def evaluate_pqc_state(classical_parsed: Dict[str, Any],
                       oqs_parsed: Dict[str, Any]) -> Dict[str, Any]:

    pqc = {
        "negotiated": [],
        "supported": [],
        "classification": {},
        "confidence": "high"
    }

    c_key = classical_parsed.get("negotiated", {}).get("server_temp_key")
    o_key = oqs_parsed.get("negotiated", {}).get("server_temp_key")

    c_pqc = extract_pqc_group(c_key)
    o_pqc = extract_pqc_group(o_key)

    if c_pqc:
        pqc["negotiated"].append(c_pqc)
        pqc["classification"][c_pqc] = classify_pqc(c_pqc)

    if o_pqc and o_pqc not in pqc["negotiated"]:
        pqc["supported"].append(o_pqc)
        pqc["classification"][o_pqc] = classify_pqc(o_pqc)

    return pqc


# =============================================================================
# PFS Detection
# =============================================================================

def has_pfs(value: str | None) -> bool:
    if not value:
        return False
    v = value.upper()
    return any(x in v for x in ["ECDHE", "DHE", "X25519", "X448"])


# =============================================================================
# MAIN ENRICH FUNCTION
# =============================================================================

def enrich_scan(
    classical_parsed: Dict[str, Any],
    oqs_parsed: Dict[str, Any],
    nmap_parsed: Dict[str, Any],
    testssl_parsed: Dict[str, Any],
    domain: str
) -> Dict[str, Any]:

    # -------------------------------------------------------------------------
    # 0. Short-circuit if scan failed
    # -------------------------------------------------------------------------
    status = classical_parsed.get("status", "success")
    if status != "success":
        return {
            "status": status,
            "failure_reason": classical_parsed.get("failure_reason"),
            "negotiated": None,
            "certificate": None,
            "pqc": None,
            "supported": {
                "tls_versions": [],
                "cipher_suites": []
            },
            "weak_ciphers": [],
            "vulnerabilities": [],
            "pfs_supported": False
        }

    enriched = {
        "status": "success",
        "failure_reason": None,
        "negotiated": classical_parsed.get("negotiated", {}).copy(),
        "certificate": classical_parsed.get("certificate", {}).copy(),
        "supported": {
            "tls_versions": [],
            "cipher_suites": []
        },
        "weak_ciphers": [],
        "vulnerabilities": [],
        "pqc": None # Will be populated below
    }

    # ---------------- PQC ----------------
    enriched["pqc"] = evaluate_pqc_state(classical_parsed, oqs_parsed)

    # ---------------- TLS versions ----------------
    tls_versions = set()

    if enriched["negotiated"].get("tls_version"):
        tls_versions.add(enriched["negotiated"]["tls_version"])

    tls_versions.update(nmap_parsed.get("tls_versions", []))
    tls_versions.update(testssl_parsed.get("tls_versions", []))

    enriched["supported"]["tls_versions"] = sorted(tls_versions)

    # ---------------- Cipher suites ----------------
    seen = set()
    cipher_list = []

    def add_cipher(c):
        if not c or c in seen:
            return
        seen.add(c)
        cipher_list.append(c)

    add_cipher(enriched["negotiated"].get("cipher"))

    for c in nmap_parsed.get("cipher_suites", []):
        add_cipher(c)

    for c in testssl_parsed.get("cipher_suites", []):
        add_cipher(c)

    enriched["supported"]["cipher_suites"] = cipher_list

    # ---------------- Key exchange ----------------
    temp_key = enriched["negotiated"].get("server_temp_key")
    kex = temp_key.split(",")[0].strip() if temp_key else None

    enriched["negotiated"]["key_exchange"] = kex

    # ---------------- PFS ----------------
    enriched["pfs_supported"] = has_pfs(kex)

    if not enriched["pfs_supported"]:
        for c in cipher_list:
            if has_pfs(c):
                enriched["pfs_supported"] = True
                break

    # ---------------- Vulnerabilities ----------------
    enriched["vulnerabilities"] = sorted(set(testssl_parsed.get("vulnerabilities", [])))

    # ---------------- Certificate History ----------------
    enriched["certificate"]["certificate_history"] = get_certificate_history(domain)

    # ---------------- Fallback from testssl ----------------
    if not enriched["certificate"].get("issuer"):
        enriched["certificate"]["issuer"] = testssl_parsed.get("issuer")

    if not enriched["certificate"].get("expires"):
        enriched["certificate"]["expires"] = testssl_parsed.get("expires")

    return enriched