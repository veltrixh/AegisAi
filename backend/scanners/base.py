from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from backend.models.finding import FindingModel
from backend.utils.http_client import AsyncScannerClient

class BaseScanner(ABC):
    """
    Abstract Base Class for all vulnerability and configuration scanners.
    Every scanner must implement a deterministic scan method producing structured findings.
    """
    name: str = "BaseScanner"
    vulnerability_type: str = "general"
    category: str = "active"  # "active" or "passive"
    enabled: bool = True

    def __init__(self, client: Optional[AsyncScannerClient] = None):
        self.client = client

    @abstractmethod
    async def scan(self, target: str, context: Dict[str, Any]) -> List[FindingModel]:
        """
        Executes scanner against target URL with provided context.
        Context can contain:
          - 'baseline': ScannerResponse
          - 'discovered_endpoints': List[str]
          - 'discovered_forms': List[Dict]
          - 'parameters': List[str]
          - 'openapi_spec': Optional[Dict]
        Returns a list of structured FindingModels with evidence.
        """
        pass
