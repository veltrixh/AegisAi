from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from backend.models.finding import FindingModel
from backend.models.attack_path import AttackGraphModel, VulnerabilityCorrelation

class ScanConfig(BaseModel):
    target_url: str
    profile: str = "standard"  # quick, standard, deep, passive, api, full
    max_concurrency: int = 5
    rate_limit: float = 15.0
    timeout: float = 10.0
    allow_local: bool = True
    openapi_spec: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)

class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0

class ScanSummary(BaseModel):
    total_findings: int = 0
    severity_breakdown: SeverityBreakdown = Field(default_factory=SeverityBreakdown)
    security_score: float = 100.0  # 0 - 100
    top_risks: List[Dict[str, Any]] = Field(default_factory=list)

class ScanModel(BaseModel):
    id: str
    target_url: str
    profile: str = "standard"
    status: str = "pending"  # pending, running, completed, failed, cancelled
    progress: int = 0        # 0 - 100
    current_phase: str = "Initialized"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    duration_seconds: float = 0.0
    config: ScanConfig
    summary: ScanSummary = Field(default_factory=ScanSummary)
    findings: List[FindingModel] = Field(default_factory=list)
    correlations: List[VulnerabilityCorrelation] = Field(default_factory=list)
    attack_graph: AttackGraphModel = Field(default_factory=AttackGraphModel)
    error_message: Optional[str] = None

class ScanComparisonResult(BaseModel):
    base_scan_id: str
    target_scan_id: str
    new_findings: List[FindingModel] = Field(default_factory=list)
    fixed_findings: List[FindingModel] = Field(default_factory=list)
    unchanged_findings: List[FindingModel] = Field(default_factory=list)
    regressed_findings: List[FindingModel] = Field(default_factory=list)
    score_before: float
    score_after: float
    score_improvement: float
    summary: Dict[str, int] = Field(default_factory=dict)
