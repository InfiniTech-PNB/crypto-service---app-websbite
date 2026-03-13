# =============================================================================
# models.py — Pydantic Models for Crypto Scanner (PQC Enabled)
# =============================================================================

from pydantic import BaseModel, Field, IPvAnyAddress
from typing import List, Optional, Literal


# -----------------------------------------------------------------------------
# Service model
# -----------------------------------------------------------------------------

class ServiceInput(BaseModel):

    port: int = Field(
        ...,
        ge=1,
        le=65535,
        description="TCP port number",
        example=443,
    )

    protocol_name: str = Field(
        ...,
        description="Protocol name (HTTPS, SMTPS, IMAPS, etc)",
        example="HTTPS",
    )


# -----------------------------------------------------------------------------
# Asset model
# -----------------------------------------------------------------------------

class AssetInput(BaseModel):

    host: str = Field(
        ...,
        description="Hostname",
        example="api.github.com",
    )

    ip: IPvAnyAddress = Field(
        ...,
        description="IPv4 or IPv6 address",
        example="20.207.73.85",
    )

    services: List[ServiceInput] = Field(
        ...,
        description="List of open services",
    )


# -----------------------------------------------------------------------------
# Scan request
# -----------------------------------------------------------------------------

class ScanRequest(BaseModel):

    assets: List[AssetInput] = Field(
        ...,
        description="Assets to scan",
    )

    scan_type: Literal["soft", "deep"] = Field(
        default="soft",
        description="Scan intensity: soft (OpenSSL + Nmap) or deep (+ testssl)",
    )


# -----------------------------------------------------------------------------
# Scan result
# -----------------------------------------------------------------------------

class ScanResult(BaseModel):

    host: str = Field(..., description="Hostname")
    ip: str = Field(..., description="IP address")
    port: int = Field(..., description="TCP port")
    protocol: str = Field(..., description="Protocol name")

    # ------------------------------------------------------------------
    # Negotiated TLS values
    # ------------------------------------------------------------------

    tls_version: Optional[str] = Field(
        None,
        description="Negotiated TLS/SSL version (TLSv1.2, TLSv1.3, SSLv3)",
    )

    cipher: Optional[str] = Field(
        None,
        description="Negotiated cipher suite",
    )

    key_exchange: Optional[str] = Field(
        None,
        description="Key exchange algorithm (ECDHE, RSA, X25519, MLKEM, etc)",
    )

    signature_algorithm: Optional[str] = Field(
        None,
        description="Certificate signature algorithm",
    )

    # ------------------------------------------------------------------
    # PQC detection
    # ------------------------------------------------------------------

    pqc_key_exchange: Optional[str] = Field(
        None,
        description="Detected PQC key exchange algorithm (MLKEM/Kyber)",
    )

    pqc_signature: Optional[str] = Field(
        None,
        description="Detected PQC signature algorithm (Dilithium, Falcon, SPHINCS)",
    )

    hybrid_pqc: bool = Field(
        False,
        description="Whether hybrid PQC TLS (classical + PQC) is used",
    )

    # ------------------------------------------------------------------
    # Enumerated TLS configuration
    # ------------------------------------------------------------------

    supported_tls_versions: List[str] = Field(
        default_factory=list,
        description="All supported TLS/SSL protocol versions",
    )

    cipher_suites: List[str] = Field(
        default_factory=list,
        description="All supported cipher suites",
    )

    weak_ciphers: List[str] = Field(
        default_factory=list,
        description="Weak or insecure ciphers detected",
    )

    # ------------------------------------------------------------------
    # Certificate information
    # ------------------------------------------------------------------

    key_size: Optional[int] = Field(
        None,
        description="Certificate public key size in bits",
        example=2048,
    )

    issuer: Optional[str] = Field(
        None,
        description="Certificate issuer",
    )

    expires: Optional[str] = Field(
        None,
        description="Certificate expiration date (YYYY-MM-DD)",
    )

    # ------------------------------------------------------------------
    # Security posture
    # ------------------------------------------------------------------

    pfs_supported: bool = Field(
        False,
        description="Perfect Forward Secrecy supported",
    )

    vulnerabilities: List[str] = Field(
        default_factory=list,
        description="Detected TLS vulnerabilities",
    )

    self_signed: bool = Field(
        False,
        description="Whether certificate is self-signed",
    )

    # ------------------------------------------------------------------
    # Optional: PQC readiness score (for ML)
    # ------------------------------------------------------------------

    pqc_ready_score: Optional[float] = Field(
        None,
        description="Post-quantum readiness score (0.0–1.0)",
    )


# -----------------------------------------------------------------------------
# API response
# -----------------------------------------------------------------------------

class ScanResponse(BaseModel):

    results: List[ScanResult] = Field(
        default_factory=list,
        description="Cryptographic scan results",
    )
# -----------------------------------------------------------------------------
# CBOM models
# -----------------------------------------------------------------------------

class CBOMRequest(BaseModel):
    results: List[ScanResult]