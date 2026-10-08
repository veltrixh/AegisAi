from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from backend.models.finding import FindingModel
from backend.models.attack_path import AttackGraphModel, VulnerabilityCorrelation
from backend.api.storage import ScanStore

router = APIRouter(tags=["Findings & Attack Graph"])

@router.get("/api/scans/{scan_id}/findings", response_model=List[FindingModel])
async def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, etc.)"),
    min_confidence: Optional[float] = Query(None, description="Minimum confidence threshold (0-100)"),
    finding_type: Optional[str] = Query(None, description="Filter by vulnerability type")
):
    """Retrieves findings for a specific scan with optional severity/confidence filters."""
    scan = ScanStore.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

    findings = scan.findings
    if severity:
        findings = [f for f in findings if f.severity.upper() == severity.upper()]
    if min_confidence is not None:
        findings = [f for f in findings if f.confidence >= min_confidence]
    if finding_type:
        findings = [f for f in findings if finding_type.lower() in f.type.lower()]

    return findings

@router.get("/api/findings/{finding_id}", response_model=FindingModel)
async def get_finding(finding_id: str):
    """Retrieves full evidence and details for an individual finding across all scans."""
    for s in ScanStore.list_all():
        for f in s.findings:
            if f.finding_id == finding_id:
                return f
    raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")

@router.get("/api/scans/{scan_id}/attack-paths", response_model=AttackGraphModel)
async def get_scan_attack_paths(scan_id: str):
    """Retrieves the synthesized directed attack graph (nodes, edges, chains) for a scan."""
    scan = ScanStore.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    return scan.attack_graph

@router.get("/api/scans/{scan_id}/correlations", response_model=List[VulnerabilityCorrelation])
async def get_scan_correlations(scan_id: str):
    """Retrieves correlated vulnerability clusters and compounded threat relationships."""
    scan = ScanStore.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    return scan.correlations
