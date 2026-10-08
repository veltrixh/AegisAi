from backend.core.evidence import EvidenceCollector
from backend.core.risk_engine import RiskEngine
from backend.core.correlation import VulnerabilityCorrelationEngine
from backend.core.attack_graph import AttackPathEngine

__all__ = [
    "EvidenceCollector",
    "RiskEngine",
    "VulnerabilityCorrelationEngine",
    "AttackPathEngine",
    "run_scan",
    "ScanOrchestrator"
]

def __getattr__(name: str):
    if name == "run_scan":
        from backend.core.scanner import run_scan
        return run_scan
    elif name == "ScanOrchestrator":
        from backend.core.orchestrator import ScanOrchestrator
        return ScanOrchestrator
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
