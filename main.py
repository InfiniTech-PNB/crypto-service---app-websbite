# =============================================================================
# main.py — FastAPI Entry Point (FINAL)
# =============================================================================

import logging
import asyncio
from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.middleware.cors import CORSMiddleware

from asset_discovery.models import DiscoveryRequest, DiscoveryResult
from asset_discovery.asset_discovery import discover_assets

from crypto_scanner.models import ScanRequest, ScanResponse, CBOMRequest
from crypto_scanner.crypto_scanner import scan_assets
from crypto_scanner.cbom_generator import generate_cbom

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
    description="Asset discovery + crypto scanner",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# GLOBAL STATE
# ---------------------------------------------------------------------------
connections = {}   # jobId -> WebSocket
log_buffer = {}    # jobId -> logs

# ---------------------------------------------------------------------------
# LOG SENDER
# ---------------------------------------------------------------------------
async def send_log(job_id: str, message: str):
    log_buffer.setdefault(job_id, []).append(message)

    ws = connections.get(job_id)
    if ws:
        await ws.send_text(message)


# ---------------------------------------------------------------------------
# WEBSOCKET ENDPOINT
# ---------------------------------------------------------------------------
@app.websocket("/ws/logs")
async def logs_ws(ws: WebSocket, jobId: str):
    await ws.accept()

    # replay old logs
    for log in log_buffer.get(jobId, []):
        await ws.send_text(log)

    connections[jobId] = ws

    try:
        while True:
            await ws.receive_text()  # keep connection alive
    except:
        connections.pop(jobId, None)


# ---------------------------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------------------------
@app.get("/health", tags=["System"])
async def health_check():
    return {"status": "healthy", "service": "crypto-service"}


# ---------------------------------------------------------------------------
# DISCOVERY ENDPOINT (REAL-TIME LOGS + FULL RESULT)
# ---------------------------------------------------------------------------
@app.post("/discover", response_model=DiscoveryResult, tags=["Discovery"])
async def discover(request: DiscoveryRequest):
    domain = request.domain.strip().lower()
    job_id = request.jobId

    if not domain:
        raise HTTPException(status_code=400, detail="Domain cannot be empty")

    if "." not in domain or len(domain) < 3:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid domain format: {domain}",
        )

    logger.info("Received discovery request for domain: %s", domain)

    loop = asyncio.get_running_loop()

    try:
        # 🔥 bridge logs from thread → async loop
        def log_func(msg):
            loop.call_soon_threadsafe(
                asyncio.create_task,
                send_log(job_id, msg)
            )

        # 🔥 run discovery in thread (prevents blocking → enables live logs)
        result = await asyncio.to_thread(
            discover_assets,
            domain,
            log_func
        )

        logger.info(
            "Discovery complete for %s — %d assets found",
            domain,
            result["total_assets_found"],
        )

        await send_log(job_id, "[Discovery] Complete")

        return result  # ✅ CRITICAL: keep original behavior

    except Exception as e:
        logger.error("Discovery failed for %s: %s", domain, e, exc_info=True)

        await send_log(job_id, f"[ERROR] {str(e)}")

        raise HTTPException(
            status_code=500,
            detail=f"Discovery failed: {str(e)}",
        )


# ---------------------------------------------------------------------------
# SCAN ENDPOINT (UNCHANGED)
# ---------------------------------------------------------------------------
@app.post("/scan", response_model=ScanResponse, tags=["Scanner"])
async def scan(request: ScanRequest):
    if not request.assets:
        raise HTTPException(status_code=400, detail="No assets provided")

    logger.info(
        "Received scan request — %d assets, type=%s",
        len(request.assets),
        request.scan_type,
    )

    try:
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
# CBOM ENDPOINT (RESTORED SAFE VERSION)
# ---------------------------------------------------------------------------
@app.post("/cbom", tags=["CBOM"])
async def cbom(request: CBOMRequest):

    if not request.results:
        raise HTTPException(status_code=400, detail="No scan results provided")

    logger.info("Generating CBOM for %d assets", len(request.results))

    try:
        # 🔥 safe conversion (handles dict + pydantic)
        results = [
            r.dict() if hasattr(r, "dict") else r
            for r in request.results
        ]

        mode = getattr(request, "mode", "aggregate")

        cbom_result = generate_cbom(
            {"results": results},
            mode=mode
        )

        return {
            "mode": mode,
            "cbom": cbom_result,
            "results": results   # ✅ ensures compatibility
        }

    except Exception as e:
        logger.error("CBOM generation failed: %s", e, exc_info=True)

        raise HTTPException(
            status_code=500,
            detail=f"CBOM generation failed: {str(e)}",
        )


# ---------------------------------------------------------------------------
# RUNNER
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)