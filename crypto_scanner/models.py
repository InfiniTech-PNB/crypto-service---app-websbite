# =============================================================================
# models.py — Pydantic Models for Crypto Scanner (PQC Enabled)
# =============================================================================

from pydantic import BaseModel, Field, IPvAnyAddress
from typing import List, Optional, Literal, Dict, Any


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
# Result Sub-Models
# -----------------------------------------------------------------------------

class OCSPState(BaseModel):
    supported: bool = Field(False, description="Whether OCSP response is supported/present")
    stapled: bool = Field(False, description="Whether OCSP response is stapled")


class NegotiatedTLS(BaseModel):
    tls_version: Optional[str] = Field(None, description="Negotiated TLS/SSL version")
    cipher: Optional[str] = Field(None, description="Negotiated cipher suite")
    server_temp_key: Optional[str] = Field(None, description="Raw Server Temp Key negotiated")
    server_temp_key_size: Optional[int] = Field(None, description="Server Temp Key bits")
    key_exchange: Optional[str] = Field(None, description="Classical Key exchange algorithm")
    alpn: Optional[str] = Field(None, description="ALPN protocol negotiated")
    session_reused: bool = Field(False, description="Whether session reuse is supported")
    ocsp: OCSPState = Field(default_factory=OCSPState)


class SupportedTLS(BaseModel):
    tls_versions: List[str] = Field(default_factory=list, description="All supported TLS/SSL protocol versions")
    cipher_suites: List[str] = Field(default_factory=list, description="All supported cipher suites")


class PQCSecurity(BaseModel):
    negotiated: List[str] = Field(default_factory=list, description="PQC algorithms negotiated")
    supported: List[str] = Field(default_factory=list, description="PQC algorithms supported via OQS")
    classification: Dict[str, str] = Field(default_factory=dict, description="Mappings to pure or hybrid")
    confidence: str = Field("high", description="Confidence level of detection (low, medium, high)")


class CertHistoryEntry(BaseModel):
    issuer: str
    not_before: str
    not_after: str


class CertExtensions(BaseModel):
    key_usage: List[str] = Field(default_factory=list)
    extended_key_usage: List[str] = Field(default_factory=list)
    basic_constraints: Dict[str, Any] = Field(default_factory=dict)


class PublicKey(BaseModel):
    type: str = Field(..., description="Key type (RSA, EC, etc.)")
    size: Optional[int] = Field(None, description="Key size in bits")


class CertificateInfo(BaseModel):
    subject: Optional[str] = None
    san: List[str] = Field(default_factory=list)
    san_count: int = 0
    issuer: Optional[str] = None
    expires: Optional[str] = None
    not_before: Optional[str] = None
    signature_algorithm: Optional[str] = None
    raw_signature_algorithm: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    public_key: Optional[PublicKey] = None
    self_signed: bool = False
    extensions: CertExtensions = Field(default_factory=CertExtensions)
    certificate_history: List[CertHistoryEntry] = Field(default_factory=list)
    certificate_chain: List[Dict[str, Any]] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# Scan result
# -----------------------------------------------------------------------------

class ScanResult(BaseModel):
    host: str = Field(..., description="Hostname")
    ip: str = Field(..., description="IP address")
    port: int = Field(..., description="TCP port")
    protocol: str = Field(..., description="Protocol name")

    status: Literal["success", "failed", "blocked"] = Field("success", description="Scan status")
    failure_reason: Optional[str] = Field(None, description="Reason for failure if status is not success")

    negotiated: Optional[NegotiatedTLS] = Field(None, description="Negotiated TLS details")
    supported: Optional[SupportedTLS] = Field(None, description="Supported TLS versions and ciphers")
    pqc: Optional[PQCSecurity] = Field(None, description="Post-Quantum Cryptography details")
    certificate: Optional[CertificateInfo] = Field(None, description="Certificate details")

    weak_ciphers: List[str] = Field(default_factory=list)
    pfs_supported: bool = False
    vulnerabilities: List[str] = Field(default_factory=list)


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
    mode: Optional[str] = Field(
        default="aggregate",
        description="CBOM generation mode: 'aggregate' or 'per_asset'"
    )
    results: List[ScanResult]