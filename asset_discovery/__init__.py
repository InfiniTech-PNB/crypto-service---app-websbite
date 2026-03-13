# =============================================================================
# Asset Discovery Package
# =============================================================================
# Public-facing asset discovery engine for cryptographic analysis.
# Discovers subdomains, resolves IPs, scans ports, and classifies services.
# =============================================================================

from asset_discovery.asset_discovery import discover_assets

__all__ = ["discover_assets"]
