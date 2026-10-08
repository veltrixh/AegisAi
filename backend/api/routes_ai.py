from fastapi import APIRouter, HTTPException
from typing import Optional, Dict, Any
from pydantic import BaseModel

from backend.api.storage import ScanStore
from backend.ai.analyst import AISecurityAnalyst
from backend.ai.explainer import ExplainableAIEngine
from backend.ai.remediation import RemediationEngine

router = APIRouter(prefix="/api/ai", tags=["AI Security Analyst & XAI"])

class AnalystQueryRequest(BaseModel):
    question: str
    scan_id: str
    finding_id: Optional[str] = None
    previous_scan_id: Optional[str] = None

@router.post("/analyze")
async def ask_analyst(req: AnalystQueryRequest):
    """
    Submits an inquiry to the evidence-grounded AI Security Analyst.
    Enforces truthfulness and distinguishes Observed, Inferred, and Recommended.
    """
    scan = ScanStore.get(req.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{req.scan_id}' not found.")

    selected_finding = None
    if req.finding_id:
        selected_finding = next((f for f in scan.findings if f.finding_id == req.finding_id), None)

    previous_scan = None
    if req.previous_scan_id:
        previous_scan = ScanStore.get(req.previous_scan_id)

    return await AISecurityAnalyst.ask(
        question=req.question,
        scan=scan,
        selected_finding=selected_finding,
        previous_scan=previous_scan
    )

class ExplainRequest(BaseModel):
    finding_id: str
    scan_id: str

@router.post("/explain")
async def explain_finding(req: ExplainRequest):
    """Generates an auditable Explainable AI report for a specific finding."""
    scan = ScanStore.get(req.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{req.scan_id}' not found.")

    finding = next((f for f in scan.findings if f.finding_id == req.finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{req.finding_id}' not found.")

    return await ExplainableAIEngine.explain(finding)

class RemediateRequest(BaseModel):
    finding_id: str
    scan_id: str

@router.post("/remediate")
async def remediate_finding(req: RemediateRequest):
    """Generates an actionable multi-language remediation blueprint for a specific finding."""
    scan = ScanStore.get(req.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{req.scan_id}' not found.")

    finding = next((f for f in scan.findings if f.finding_id == req.finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{req.finding_id}' not found.")

    return await RemediationEngine.generate_remediation(finding)
