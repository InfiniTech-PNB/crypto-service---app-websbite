# =============================================================================
# main.py — FastAPI Entry Point
# =============================================================================
# Provides a REST API for the crypto-service:
#
# Endpoints:
#   POST /discover  — Discover public-facing assets of a domain
#   POST /scan      — Scan assets for TLS/crypto configuration (CBOM)
#   GET  /health    — Health check
#
# Configures CORS, structured logging, and orchestrates both pipelines.
# =============================================================================

import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from asset_discovery.models import DiscoveryRequest, DiscoveryResult
from asset_discovery.asset_discovery import discover_assets
from crypto_scanner.models import ScanRequest, ScanResponse
from crypto_scanner.crypto_scanner import scan_assets
from crypto_scanner.cbom_generator import generate_cbom
from crypto_scanner.models import CBOMRequest
# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("main")

# ---------------------------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Crypto Service",
    description=(
        "Asset discovery and cryptographic analysis service. "
        "Discovers public-facing assets and generates a "
        "Cryptographic Bill of Materials (CBOM)."
    ),
    version="1.0.0",
)

# CORS — allow all origins for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Health Check
# ---------------------------------------------------------------------------
@app.get("/health", tags=["System"])
async def health_check():
    """
    Health check endpoint. Returns service status.
    """
    return {"status": "healthy", "service": "crypto-service"}


# ---------------------------------------------------------------------------
# Asset Discovery Endpoint
# ---------------------------------------------------------------------------
@app.post("/discover", response_model=DiscoveryResult, tags=["Discovery"])
async def discover(request: DiscoveryRequest):
    """
    Discover all public-facing assets for the given domain.

    Runs the full pipeline:
        1. Passive subdomain discovery (CT logs, Bufferover, ThreatCrowd)
        2. Active DNS brute force (120+ prefixes)
        3. DNS resolution with IP validation
        4. Port scanning for crypto-relevant services
        5. Asset classification

    Returns structured JSON with all discovered assets ready for
    downstream TLS analysis and CBOM generation.

    **Request Body:**
    ```json
    { "domain": "github.com" }
    ```

    **Response:** DiscoveryResult with domain, total_assets_found, and assets list.
    """
    domain = request.domain.strip().lower()

    if not domain:
        raise HTTPException(status_code=400, detail="Domain cannot be empty")

    # Basic domain format validation
    if "." not in domain or len(domain) < 3:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid domain format: {domain}",
        )

    logger.info("Received discovery request for domain: %s", domain)

    try:
        result = discover_assets(domain)
        logger.info(
            "Discovery complete for %s — %d assets found",
            domain,
            result["total_assets_found"],
        )
        return result
    except Exception as e:
        logger.error("Discovery failed for %s: %s", domain, e, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Discovery failed: {str(e)}",
        )


# ---------------------------------------------------------------------------
# Crypto Scan Endpoint
# ---------------------------------------------------------------------------
@app.post("/scan", response_model=ScanResponse, tags=["Scanner"])
async def scan(request: ScanRequest):
    """
    Scan selected assets for TLS/cryptographic configuration.

    Analyzes TLS versions, cipher suites, key exchange algorithms,
    certificate info, and vulnerabilities to generate a CBOM.

    **scan_type:**
    - `soft` — OpenSSL + Nmap scanning
    - `deep` — OpenSSL + Nmap + testssl.sh (slower, more comprehensive)

    **Request Body:**
    ```json
    {
      "assets": [{"host": "api.example.com", "ip": "1.2.3.4", "services": [{"port": 443, "protocol_name": "HTTPS"}]}],
      "scan_type": "soft"
    }
    ```
    """
    if not request.assets:
        raise HTTPException(status_code=400, detail="No assets provided")

    logger.info(
        "Received scan request — %d assets, type=%s",
        len(request.assets),
        request.scan_type,
    )

    try:
        # Convert Pydantic models to dicts for the scanner
        assets_data = [
            {
                "host": asset.host,
                "ip": asset.ip,
                "services": [
                    {"port": svc.port, "protocol_name": svc.protocol_name}
                    for svc in asset.services
                ],
            }
            for asset in request.assets
        ]

        result = scan_assets(assets_data, request.scan_type)
        logger.info(
            "Scan complete — %d results generated",
            len(result.get("results", [])),
        )
        return result

    except Exception as e:
        logger.error("Scan failed: %s", e, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {str(e)}",
        )

# ---------------------------------------------------------------------------
# CBOM Endpoint
# ---------------------------------------------------------------------------
@app.post("/cbom", tags=["CBOM"])
async def cbom(request: CBOMRequest):

    if not request.results:
        raise HTTPException(status_code=400, detail="No scan results provided")

    logger.info("Generating CBOM for %d assets", len(request.results))

    try:
        results = [r.dict() for r in request.results]

        mode = request.mode if hasattr(request, "mode") else "aggregate"

        cbom_result = generate_cbom(
            {"results": results},
            mode=mode
        )

        return {
            "mode": mode,
            "cbom": cbom_result
        }

    except Exception as e:
        logger.error("CBOM generation failed: %s", e, exc_info=True)

        raise HTTPException(
            status_code=500,
            detail=f"CBOM generation failed: {str(e)}",
        )    
# ---------------------------------------------------------------------------
# CLI runner — `python main.py` starts the server
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
