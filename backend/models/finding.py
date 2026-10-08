from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from backend.models.evidence import EvidenceModel

class FindingModel(BaseModel):
    finding_id: str
    scan_id: str = ""
    type: str
    title: str
    target: str
    parameter: Optional[str] = None
    method: str = "GET"
    severity: str = "MEDIUM"        # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    risk_score: float = 5.0         # 0.0 - 10.0
    cvss: float = 5.0
    cvss_vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    confidence: float = 85.0        # 0 - 100
    confidence_factors: Dict[str, float] = Field(default_factory=dict)
    validation_status: str = "Likely"  # Confirmed, Likely, Suspicious, Potential False Positive
    owasp: Dict[str, Any] = Field(default_factory=dict)
    cwe: Dict[str, Any] = Field(default_factory=dict)
    evidence: EvidenceModel
    ai_explanation: Optional[Dict[str, Any]] = None
    remediation: Optional[Dict[str, Any]] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_summary_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "type": self.type,
            "title": self.title,
            "target": self.target,
            "parameter": self.parameter,
            "method": self.method,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "cvss": self.cvss,
            "confidence": self.confidence,
            "validation_status": self.validation_status,
            "cwe_id": self.cwe.get("id"),
            "owasp_id": self.owasp.get("id")
        }
