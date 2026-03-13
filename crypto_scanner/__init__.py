# =============================================================================
# Crypto Scanner Package
# =============================================================================
# TLS/cryptographic configuration analyzer for CBOM generation.
# Scans assets discovered by asset_discovery for cipher suites,
# TLS versions, key exchange algorithms, and vulnerabilities.
# =============================================================================

from crypto_scanner.crypto_scanner import scan_assets

__all__ = ["scan_assets"]
