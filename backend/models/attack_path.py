from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # entrypoint, vector, vulnerability, asset, impact
    finding_id: Optional[str] = None
    severity: Optional[str] = None
    risk_score: Optional[float] = None
    confidence: Optional[float] = None
    details: Dict[str, Any] = Field(default_factory=dict)

class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str
    relationship: str
    weight: float = 1.0

class AttackChain(BaseModel):
    chain_id: str
    name: str
    description: str
    path_nodes: List[str]
    cumulative_risk: float
    likelihood: float
    impact_level: str

class AttackGraphModel(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    risk: float = 0.0
    chains: List[AttackChain] = Field(default_factory=list)

class VulnerabilityCorrelation(BaseModel):
    correlation_id: str
    relationship_type: str
    findings_involved: List[str]
    confidence: float
    reason: str
    compounded_risk_score: float
