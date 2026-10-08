import asyncio
from fastapi import APIRouter, HTTPException, BackgroundTasks, Query
from typing import List, Optional
from pydantic import BaseModel

from backend.models.scan import ScanModel, ScanConfig, ScanComparisonResult
from backend.core.orchestrator import ScanOrchestrator
from backend.core.comparison import ScanComparisonEngine
from backend.api.storage import ScanStore
from backend.utils.logger import logger

router = APIRouter(prefix="/api/scans", tags=["Scans"])

async def _run_scan_task(orchestrator: ScanOrchestrator):
    try:
        def on_progress(model: ScanModel):
            ScanStore.save(model)

        orchestrator.on_progress_update = on_progress
        ScanStore.save(orchestrator.scan_model)
        final_model = await orchestrator.execute()
        ScanStore.save(final_model)
    except Exception as e:
        logger.error(f"Scan task execution failed: {e}")
        orchestrator.scan_model.status = "failed"
        orchestrator.scan_model.error_message = str(e)
        ScanStore.save(orchestrator.scan_model)

@router.post("", response_model=ScanModel)
async def launch_scan(config: ScanConfig, background_tasks: BackgroundTasks):
    """Initiates an asynchronous security vulnerability assessment scan."""
    orchestrator = ScanOrchestrator(config)
    ScanStore.register_orchestrator(orchestrator.scan_id, orchestrator)
    ScanStore.save(orchestrator.scan_model)

    background_tasks.add_task(_run_scan_task, orchestrator)
    return orchestrator.scan_model

@router.get("", response_model=List[ScanModel])
async def list_scans():
    """Lists all active and historical vulnerability scans."""
    return ScanStore.list_all()

@router.get("/compare", response_model=ScanComparisonResult)
async def compare_scans(
    scan_a: str = Query(..., description="Baseline scan ID"),
    scan_b: str = Query(..., description="Target scan ID")
):
    """Compares two scans to evaluate resolved vulnerabilities, regressions, and posture score changes."""
    model_a = ScanStore.get(scan_a)
    model_b = ScanStore.get(scan_b)
    if not model_a or not model_b:
        raise HTTPException(status_code=404, detail="One or both scan IDs not found.")

    return ScanComparisonEngine.compare(model_a, model_b)

@router.get("/{scan_id}", response_model=ScanModel)
async def get_scan(scan_id: str):
    """Retrieves full status, progress, findings, and attack graph for a scan."""
    scan = ScanStore.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    return scan

@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """Cancels a running scan."""
    orch = ScanStore.get_orchestrator(scan_id)
    if orch:
        orch.cancel()
        ScanStore.save(orch.scan_model)
        return {"status": "success", "message": f"Scan {scan_id} cancelled."}

    scan = ScanStore.get(scan_id)
    if scan:
        scan.status = "cancelled"
        ScanStore.save(scan)
        return {"status": "success", "message": f"Scan {scan_id} marked as cancelled."}

    raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

class OpenApiScanRequest(BaseModel):
    target_url: str
    openapi_spec: str
    profile: str = "api"

@router.post("/openapi", response_model=ScanModel)
async def scan_openapi_spec(req: OpenApiScanRequest, background_tasks: BackgroundTasks):
    """Launches an API security audit against an uploaded OpenAPI / Swagger definition."""
    config = ScanConfig(
        target_url=req.target_url,
        profile="api",
        openapi_spec=req.openapi_spec
    )
    orchestrator = ScanOrchestrator(config)
    ScanStore.register_orchestrator(orchestrator.scan_id, orchestrator)
    ScanStore.save(orchestrator.scan_model)

    background_tasks.add_task(_run_scan_task, orchestrator)
    return orchestrator.scan_model
