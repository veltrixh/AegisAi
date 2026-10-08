from typing import Optional, Dict, Any
from backend.models.scan import ScanConfig, ScanModel
from backend.core.orchestrator import ScanOrchestrator

async def run_scan(
    target_url: str,
    profile: str = "standard",
    max_concurrency: int = 5,
    rate_limit: float = 15.0,
    timeout: float = 10.0,
    allow_local: bool = True,
    openapi_spec: Optional[str] = None
) -> ScanModel:
    """Convenience function to run a complete scan asynchronously and return ScanModel."""
    config = ScanConfig(
        target_url=target_url,
        profile=profile,
        max_concurrency=max_concurrency,
        rate_limit=rate_limit,
        timeout=timeout,
        allow_local=allow_local,
        openapi_spec=openapi_spec
    )
    orchestrator = ScanOrchestrator(config)
    return await orchestrator.execute()
