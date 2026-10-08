from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

class RequestEvidence(BaseModel):
    method: str = "GET"
    url: str
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)

class ResponseEvidence(BaseModel):
    status_code: int = 0
    response_time_ms: float = 0.0
    content_length: int = 0
    snippet: str = ""
    headers: Dict[str, str] = Field(default_factory=dict)

class EvidenceModel(BaseModel):
    baseline_response_length: int = 0
    test_response_length: int = 0
    length_diff: int = 0
    status_code_changed: bool = False
    baseline_status_code: int = 200
    test_status_code: int = 200
    response_time_changed: bool = False
    baseline_time_ms: float = 0.0
    test_time_ms: float = 0.0
    error_signature: Optional[str] = None
    payload_category: str = "general"
    payloads_tested: int = 1
    successful_payloads: int = 1
    reproducible: bool = True
    reproduction_count: int = 1
    detection_rule: str = "behavioral_heuristic"
    behavioral_changes: Dict[str, Any] = Field(default_factory=dict)
    request: Optional[RequestEvidence] = None
    response: Optional[ResponseEvidence] = None
    diff_summary: Optional[str] = None
