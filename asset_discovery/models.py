# =============================================================================
# models.py — Pydantic Data Models
# =============================================================================
# Defines the request/response schemas for the asset discovery pipeline.
# These models enforce type safety and produce clean JSON serialization.
# =============================================================================

from pydantic import BaseModel, Field
from typing import List


class DiscoveryRequest(BaseModel):
    """
    Incoming request payload for the /discover endpoint.

    Attributes:
        domain: The root domain to scan (e.g. "github.com").
    """
    domain: str = Field(
        ...,
        description="Root domain to discover assets for",
        examples=["github.com", "example.com"],
    )


class ServiceInfo(BaseModel):
    """
    Represents a single open network service on a host.

    Attributes:
        port: The TCP port number (e.g. 443).
        protocol_name: Human-readable protocol name (e.g. "HTTPS").
    """
    port: int = Field(..., description="TCP port number")
    protocol_name: str = Field(..., description="Protocol name (e.g. HTTPS, SSH)")


class AssetInfo(BaseModel):
    """
    Represents a single discovered asset (host) with its resolved IP,
    classification, and list of open services.

    Attributes:
        host: Fully qualified domain name.
        ip: Resolved IPv4 address.
        asset_type: Classification label (API, VPN, MAIL, WEB, etc.).
        services: List of open services detected on this host.
    """
    host: str = Field(..., description="Fully qualified hostname")
    ip: str = Field(..., description="Resolved IPv4 address")
    asset_type: str = Field(..., description="Asset classification (API, VPN, WEB, etc.)")
    services: List[ServiceInfo] = Field(
        default_factory=list,
        description="Open services detected on this host",
    )


class DiscoveryResult(BaseModel):
    """
    Top-level response returned by the discovery pipeline.

    Attributes:
        domain: The root domain that was scanned.
        total_assets_found: Count of assets with at least one open service.
        assets: List of discovered assets, sorted alphabetically by hostname.
    """
    domain: str = Field(..., description="Root domain scanned")
    total_assets_found: int = Field(..., description="Number of assets with open services")
    assets: List[AssetInfo] = Field(
        default_factory=list,
        description="Discovered assets sorted by hostname",
    )
