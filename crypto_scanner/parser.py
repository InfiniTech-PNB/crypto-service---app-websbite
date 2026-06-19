# =============================================================================
# parser.py — Production TLS Scanner Parser (PQC Enabled)
# =============================================================================

import re
import logging
from datetime import datetime
from typing import Dict, Any

from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("scanner")

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


def parse_certificate(pem: str):
    try:
        cert = x509.load_pem_x509_certificate(
            pem.encode(),
            default_backend()
        )
        
        public_key = cert.public_key()
        pk_info = {"type": "Unknown", "size": None}
        
        if isinstance(public_key, rsa.RSAPublicKey):
            pk_info["type"] = "RSA"
            pk_info["size"] = public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            pk_info["type"] = "EC"
            pk_info["size"] = public_key.curve.key_size
        elif hasattr(public_key, "key_size"):
            pk_info["size"] = public_key.key_size

        san_list = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = san_ext.value.get_values_for_type(x509.DNSName)
            san_list = [str(san) for san in sans]
        except x509.ExtensionNotFound:
            pass

        extensions = {
            "key_usage": [],
            "extended_key_usage": [],
            "basic_constraints": {}
        }
        
        try:
            ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
            key_usage_list = []
            if ku.digital_signature: key_usage_list.append("Digital Signature")
            if ku.content_commitment: key_usage_list.append("Content Commitment")
            if ku.key_encipherment: key_usage_list.append("Key Encipherment")
            if ku.data_encipherment: key_usage_list.append("Data Encipherment")
            if ku.key_agreement: key_usage_list.append("Key Agreement")
            if ku.key_cert_sign: key_usage_list.append("Key Cert Sign")
            if ku.crl_sign: key_usage_list.append("CRL Sign")
            extensions["key_usage"] = key_usage_list
        except x509.ExtensionNotFound:
            pass
            
        try:
            eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
            extensions["extended_key_usage"] = [oid._name for oid in eku]
        except x509.ExtensionNotFound:
            pass
            
        try:
            bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
            extensions["basic_constraints"] = {
                "ca": bc.ca,
                "path_length": bc.path_length
            }
        except x509.ExtensionNotFound:
            pass

        return {
            "issuer": cert.issuer.rfc4514_string(),
            "subject": cert.subject.rfc4514_string(),
            "san": san_list,
            "san_count": len(san_list),
            "not_before": cert.not_valid_before_utc.strftime("%Y-%m-%d"),
            "not_after": cert.not_valid_after_utc.strftime("%Y-%m-%d"),
            "raw_signature_algorithm": cert.signature_algorithm_oid._name,
            "signature_algorithm": normalize_sig(cert.signature_algorithm_oid._name),
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
            "public_key": pk_info,
            "extensions": extensions
        }

    except Exception as e:
        logger.warning("Certificate parsing failed: %s", e)
        return {}


# =============================================================================
# OpenSSL parser
# =============================================================================

def parse_openssl_output(raw: str, error_msg: str = None) -> Dict[str, Any]:
    # -------------------------------------------------------------------------
    # 1. Detect Handshake Failure / Blocked
    # -------------------------------------------------------------------------
    status = "success"
    failure_reason = None
    
    raw_lower = (raw or "").lower()
    error_lower = (error_msg or "").lower()

    # Blocked logic
    if "timeout" in error_lower or "reset" in error_lower:
        status = "blocked"
        failure_reason = error_msg or "Connection timed out"
    elif not raw or "cipher is (none)" in raw or "handshake failure" in raw_lower or "no peer certificate" in raw_lower:
        status = "failed"
        if "handshake failure" in raw_lower:
            failure_reason = "TLS handshake failure (mismatch)"
        elif "no peer certificate" in raw_lower:
            failure_reason = "No peer certificate provided"
        elif "cipher is (none)" in raw:
            failure_reason = "Negotiated cipher is (NONE)"
        elif error_msg:
            failure_reason = error_msg
        else:
            failure_reason = "TLS handshake failed or blocked"

    if status != "success":
        return {
            "status": status,
            "failure_reason": failure_reason,
            "negotiated": None,
            "certificate": None,
            "pqc": None,
            "supported": None
        }

    # -------------------------------------------------------------------------
    # 2. Success Path (Existing logic)
    # -------------------------------------------------------------------------
    result: Dict[str, Any] = {
        "status": "success",
        "failure_reason": None,
        "negotiated": {
            "tls_version": None,
            "cipher": None,
            "server_temp_key": None,
            "server_temp_key_size": None,
            "alpn": None,
            "session_reused": False,
            "ocsp": {
                "supported": False,
                "stapled": False,
            }
        },
        "certificate": {
            "subject": None,
            "san": [],
            "san_count": 0,
            "issuer": None,
            "not_before": None,
            "expires": None,
            "raw_signature_algorithm": None,
            "signature_algorithm": None,
            "fingerprint_sha256": None,
            "public_key": None,
            "self_signed": False,
            "extensions": {
                "key_usage": [],
                "extended_key_usage": [],
                "basic_constraints": {}
            },
            "certificate_chain": []
        }
    }

    # Certificate Information (Leaf + Chain)
    pems = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        raw,
        re.S
    )

    if pems:
        # First one is the leaf certificate
        cert_info = parse_certificate(pems[0])
        if cert_info.get("subject"):
            result["certificate"]["subject"] = cert_info["subject"]
        if cert_info.get("issuer"):
            result["certificate"]["issuer"] = cert_info["issuer"]
        if cert_info.get("san"):
            result["certificate"]["san"] = cert_info["san"]
        if cert_info.get("san_count") is not None:
            result["certificate"]["san_count"] = cert_info["san_count"]
        if cert_info.get("not_before"):
            result["certificate"]["not_before"] = cert_info["not_before"]
        if cert_info.get("not_after"):
            result["certificate"]["expires"] = cert_info["not_after"]
        if cert_info.get("signature_algorithm"):
            result["certificate"]["signature_algorithm"] = cert_info["signature_algorithm"]
        if cert_info.get("raw_signature_algorithm"):
            result["certificate"]["raw_signature_algorithm"] = cert_info["raw_signature_algorithm"]
        if cert_info.get("fingerprint_sha256"):
            result["certificate"]["fingerprint_sha256"] = cert_info["fingerprint_sha256"]
        if cert_info.get("public_key"):
            result["certificate"]["public_key"] = cert_info["public_key"]
        if "extensions" in cert_info:
            result["certificate"]["extensions"] = cert_info["extensions"]

        # Rest of them make up the certificate chain
        if len(pems) > 1:
            for pem in pems[1:]:
                result["certificate"]["certificate_chain"].append(parse_certificate(pem))

    # Self signed fallback
    if "self signed" in raw.lower():
        result["certificate"]["self_signed"] = True

    # TLS Version
    m = re.search(r"Protocol\s*:\s*((?:TLS|SSL)[^\s]+)", raw)
    if m:
        result["negotiated"]["tls_version"] = normalize_tls(m.group(1))
    if result["negotiated"]["tls_version"] is None:
        m = re.search(r"New,\s*((?:TLS|SSL)[^\s,]+)", raw)
        if m:
            result["negotiated"]["tls_version"] = normalize_tls(m.group(1))

    # Cipher
    m = re.search(r"Cipher\s*:\s*(\S+)", raw)
    if m:
        cipher = m.group(1)
        if cipher not in ["0000", "(NONE)", "0"]:
            result["negotiated"]["cipher"] = cipher
    if result["negotiated"]["cipher"] is None:
        m = re.search(r"Cipher is\s+(\S+)", raw)
        if m:
            result["negotiated"]["cipher"] = m.group(1)

    # Server Temp Key
    m = re.search(r"Server Temp Key:\s*(.+)", raw)
    if m:
        temp_key_full = m.group(1).strip()
        parts = temp_key_full.split(",")
        result["negotiated"]["server_temp_key"] = parts[0].strip()
        if len(parts) > 1:
            size_match = re.search(r"(\d+)\s*bits?", parts[-1])
            if size_match:
                result["negotiated"]["server_temp_key_size"] = int(size_match.group(1))

    # ALPN protocol (robust)
    alpn = None

    patterns = [
        r"ALPN protocol:\s*([^\s\n]+)",
        r"ALPN,\s*server accepted to use\s*([^\s\n]+)",
        r"ALPN protocols advertised by server:\s*([^\n]+)"
    ]

    for pattern in patterns:
        m = re.search(pattern, raw)
        if m:
            val = m.group(1).strip()
            if "," in val:
                val = val.split(",")[0].strip()
            alpn = val
            break

    if alpn:
        result["negotiated"]["alpn"] = alpn

    # OCSP Detect
    raw_lower = raw.lower()

    if "ocsp response" in raw_lower:
        result["negotiated"]["ocsp"]["supported"] = True

        if "no response sent" in raw_lower:
            result["negotiated"]["ocsp"]["stapled"] = False
        else:
            result["negotiated"]["ocsp"]["stapled"] = True

    # Session Reuse
    if "Reused, " in raw or "Session-ID: " in raw:
        # Check carefully for 0000 as session ID if not reused
        if "Reused," in raw:
            result["negotiated"]["session_reused"] = True

    return result

# =============================================================================
# Nmap parser
# =============================================================================

def parse_nmap_output(raw: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "tls_versions": [],
        "cipher_suites": []
    }
    if not raw:
        return result

    raw_upper = raw.upper()

    # TLS version detection
    for tls in ["TLSV1.0", "TLSV1.1", "TLSV1.2", "TLSV1.3", "SSLV3"]:
        if tls in raw_upper:
            result["tls_versions"].append(tls.replace("V", "v"))

    # Extract cipher suites (Strict matching to avoid TLS_AKE_WITH_AES_... malformed)
    # Valid ciphers typically match TLS_... but Nmap strictly prefixes with TLS_
    # Let's filter out anything that doesn't follow strict patterns
    cipher_matches = re.findall(r"TLS_[A-Z0-9_]+", raw_upper)
    for cipher in cipher_matches:
        if "AKE_WITH_" in cipher or cipher.endswith("_"):
            continue # Malformed
        if cipher not in result["cipher_suites"]:
            result["cipher_suites"].append(cipher)

    return result


# =============================================================================
# testssl.sh parser
# =============================================================================

def parse_testssl_json(data: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "tls_versions": [],
        "cipher_suites": [],
        "vulnerabilities": [],
        "issuer": None,
        "expires": None,
        "self_signed": False,
        "public_key": None,
        "certificate_algorithm": None
    }
    if not data:
        return result

    # testssl.sh JSON output format can be a list of dictionaries (findings)
    if isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict):
                continue
            entry_id = entry.get("id")
            finding = entry.get("finding", "")
            severity = entry.get("severity", "")
            result_val = entry.get("result", "")

            # Protocols
            if entry_id in ["SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"]:
                if "offered" in finding.lower() or "offered" in result_val.lower():
                    mapped = {
                        "SSLv2": "SSLv2",
                        "SSLv3": "SSLv3",
                        "TLS1": "TLSv1.0",
                        "TLS1_1": "TLSv1.1",
                        "TLS1_2": "TLSv1.2",
                        "TLS1_3": "TLSv1.3"
                    }.get(entry_id)
                    if mapped and mapped not in result["tls_versions"]:
                        result["tls_versions"].append(mapped)

            # Ciphers
            # Findings can contain cipher suite names separated by spaces, commas, or newlines
            for word in re.split(r"[\s,]+", finding):
                word_clean = word.strip().upper()
                if word_clean.startswith("TLS_") or "_WITH_" in word_clean:
                    # Clean up things like (128 bits) or hex codes
                    word_clean = re.sub(r"[^A-Z0-9_]", "", word_clean)
                    if "AKE_WITH_" in word_clean or word_clean.endswith("_"):
                        continue
                    if word_clean not in result["cipher_suites"]:
                        result["cipher_suites"].append(word_clean)

            # Vulnerabilities
            if severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"] and "not vulnerable" not in finding.lower() and "no vulnerability" not in finding.lower():
                vuln_name = entry_id or finding
                if vuln_name not in result["vulnerabilities"]:
                    result["vulnerabilities"].append(vuln_name)

            # Issuer
            if entry_id == "cert_issuer":
                result["issuer"] = finding

            # Expiry
            if entry_id in ["cert_expiration", "cert_notAfter"]:
                result["expires"] = parse_date(finding)

            # Key size / Key algorithm
            if entry_id == "cert_keySize":
                try:
                    size_match = re.search(r"(\d+)", finding)
                    if size_match:
                        result["public_key"] = {
                            "type": "Unknown",
                            "size": int(size_match.group(1))
                        }
                except:
                    pass

            if entry_id == "cert_signatureAlgorithm":
                result["certificate_algorithm"] = finding

            if entry_id == "cert_trust" and "self signed" in finding.lower():
                result["self_signed"] = True

    elif isinstance(data, dict):
        result["tls_versions"] = data.get("tls_versions", [])

        # Filter out malformed ciphers
        raw_ciphers = data.get("cipher_suites", [])
        valid_ciphers = []
        for c in raw_ciphers:
            if "AKE_WITH_" in c or c.endswith("_") or not c.upper().startswith("TLS_"):
                continue
            valid_ciphers.append(c)
        result["cipher_suites"] = valid_ciphers

        result["vulnerabilities"] = data.get("vulnerabilities", [])
        result["issuer"] = data.get("issuer")
        result["expires"] = data.get("expires")

        # Adapt legacy testssl key parsing
        ks = data.get("key_size")
        if ks:
            result["public_key"] = {
                "type": "Unknown",
                "size": ks
            }

        result["certificate_algorithm"] = data.get("certificate_algorithm")
        result["self_signed"] = data.get("self_signed", False)

    return result