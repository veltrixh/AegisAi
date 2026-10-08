import asyncio
import time
import uuid
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timezone

from backend.models.scan import ScanModel, ScanConfig, ScanSummary, SeverityBreakdown
from backend.models.finding import FindingModel
from backend.models.attack_path import AttackGraphModel, VulnerabilityCorrelation
from backend.utils.http_client import AsyncScannerClient, ScannerResponse
from backend.utils.url_validator import validate_target_url
from backend.utils.logger import logger

from backend.scanners.discovery import DiscoveryScanner
from backend.scanners.headers import SecurityHeadersScanner
from backend.scanners.tls import TLSScanner
from backend.scanners.sqli import SQLInjectionScanner
from backend.scanners.xss import XSSScanner
from backend.scanners.csrf import CSRFScanner
from backend.scanners.ssrf import SSRFScanner
from backend.scanners.api import APISecurityScanner

from backend.core.risk_engine import RiskEngine
from backend.core.correlation import VulnerabilityCorrelationEngine
from backend.core.attack_graph import AttackPathEngine
from backend.ai.explainer import ExplainableAIEngine
from backend.ai.remediation import RemediationEngine

class ScanOrchestrator:
    """
    Core Scan Orchestration Engine.
    Executes staged modular scanning pipelines:
    Discovery -> Headers -> TLS -> SQLi -> XSS -> CSRF -> SSRF -> API Security -> Correlation -> Attack Graph -> XAI
    Tracks progress, supports cancellation, computes security posture, and generates complete models.
    """

    def __init__(self, config: ScanConfig, scan_id: Optional[str] = None):
        self.scan_id = scan_id or f"SCAN-{uuid.uuid4().hex[:8].upper()}"
        self.config = config
        self.is_cancelled = False
        self.scan_model = ScanModel(
            id=self.scan_id,
            target_url=config.target_url,
            profile=config.profile,
            status="pending",
            progress=0,
            current_phase="Initialized",
            config=config
        )
        self.on_progress_update: Optional[Callable[[ScanModel], None]] = None

    def cancel(self):
        """Signals orchestrator to abort the active scan."""
        logger.info(f"Cancellation requested for scan {self.scan_id}")
        self.is_cancelled = True
        self.scan_model.status = "cancelled"
        self.scan_model.current_phase = "Cancelled by user"

    def _update_progress(self, progress: int, phase: str):
        if self.is_cancelled:
            return
        self.scan_model.progress = min(progress, 100)
        self.scan_model.current_phase = phase
        if self.on_progress_update:
            try:
                self.on_progress_update(self.scan_model)
            except Exception as e:
                logger.debug(f"Progress callback error: {e}")

    async def execute(self) -> ScanModel:
        start_time = time.time()
        self.scan_model.status = "running"
        self._update_progress(5, "Validating Target URL")

        # 1. Target Validation
        is_valid, validated_or_err = validate_target_url(
            self.config.target_url, allow_local=self.config.allow_local
        )
        if not is_valid:
            self.scan_model.status = "failed"
            self.scan_model.error_message = validated_or_err
            self.scan_model.current_phase = "Failed: Invalid target URL"
            return self.scan_model

        target = validated_or_err
        self.scan_model.target_url = target

        context: Dict[str, Any] = {
            "target": target,
            "openapi_spec": self.config.openapi_spec,
            "discovered_endpoints": [target],
            "discovered_forms": [],
            "discovered_params": []
        }

        async with AsyncScannerClient(
            timeout=self.config.timeout,
            max_concurrency=self.config.max_concurrency,
            requests_per_sec=self.config.rate_limit,
            verify_ssl=False,
            headers=self.config.headers
        ) as client:

            # 2. Stage 1: Discovery & Recon
            if self.is_cancelled:
                return self.scan_model

            self._update_progress(10, "Target Discovery & Baseline Collection")
            discovery = DiscoveryScanner(client=client)
            await discovery.scan(target, context)

            all_findings: List[FindingModel] = []
            profile = self.config.profile.lower()

            # Determine scanners to run based on profile
            # quick: headers + tls
            # standard: quick + sqli + xss + csrf + ssrf
            # deep: all + deep param permutations
            # passive: headers + tls
            # api: api scanner + discovery
            # full: all

            run_headers = profile in ("quick", "standard", "deep", "passive", "full")
            run_tls = profile in ("quick", "standard", "deep", "passive", "full")
            run_active = profile in ("standard", "deep", "full")
            run_api = profile in ("api", "deep", "full")

            # 3. Stage 2: Passive Headers & Cookies
            if run_headers and not self.is_cancelled:
                self._update_progress(20, "Passive Security Headers & Cookie Audit")
                headers_scanner = SecurityHeadersScanner(client=client)
                hdr_findings = await headers_scanner.scan(target, context)
                all_findings.extend(hdr_findings)

            # 4. Stage 3: Passive TLS & Certificate
            if run_tls and not self.is_cancelled:
                self._update_progress(30, "TLS & Transport Security Analysis")
                tls_scanner = TLSScanner(client=client)
                tls_findings = await tls_scanner.scan(target, context)
                all_findings.extend(tls_findings)

            # 5. Stage 4: SQL Injection
            if run_active and not self.is_cancelled:
                self._update_progress(45, "Deterministic SQL Injection Scanning")
                sqli_scanner = SQLInjectionScanner(client=client)
                sqli_findings = await sqli_scanner.scan(target, context)
                all_findings.extend(sqli_findings)

            # 6. Stage 5: Cross-Site Scripting (XSS)
            if run_active and not self.is_cancelled:
                self._update_progress(60, "Reflected Cross-Site Scripting (XSS) Probing")
                xss_scanner = XSSScanner(client=client)
                xss_findings = await xss_scanner.scan(target, context)
                all_findings.extend(xss_findings)

            # 7. Stage 6: CSRF Analysis
            if run_active and not self.is_cancelled:
                self._update_progress(70, "Form & Anti-CSRF Token Validation")
                csrf_scanner = CSRFScanner(client=client)
                csrf_findings = await csrf_scanner.scan(target, context)
                all_findings.extend(csrf_findings)

            # 8. Stage 7: SSRF Probing
            if run_active and not self.is_cancelled:
                self._update_progress(78, "Server-Side Request Forgery (SSRF) Probing")
                ssrf_scanner = SSRFScanner(client=client)
                ssrf_findings = await ssrf_scanner.scan(target, context)
                all_findings.extend(ssrf_findings)

            # 9. Stage 8: OpenAPI / API Security
            if run_api and not self.is_cancelled:
                self._update_progress(85, "API / OpenAPI Endpoint Security Analysis")
                api_scanner = APISecurityScanner(client=client)
                api_findings = await api_scanner.scan(target, context)
                all_findings.extend(api_findings)

            if self.is_cancelled:
                return self.scan_model

            # 10. Stage 9: Generate XAI Explanations & Actionable Remediation
            self._update_progress(90, "Generating Explainable AI & Remediation Blueprints")
            for f in all_findings:
                f.scan_id = self.scan_id
                f.ai_explanation = await ExplainableAIEngine.explain(f)
                f.remediation = await RemediationEngine.generate_remediation(f)

            # 11. Stage 10: Vulnerability Correlation
            self._update_progress(94, "Computing Vulnerability Correlation Chains")
            correlations = VulnerabilityCorrelationEngine.correlate(all_findings)

            # 12. Stage 11: Attack Path Synthesis
            self._update_progress(97, "Synthesizing Directed Attack Path Graph")
            attack_graph = AttackPathEngine.generate(target, all_findings)

            # 13. Stage 12: Risk Posture Scoring
            posture_result = RiskEngine.calculate_security_posture(
                all_findings, total_endpoints=len(context.get("discovered_endpoints", [target]))
            )

            # Compile Scan Summary
            counts = posture_result["counts"]
            breakdown = SeverityBreakdown(
                critical=counts["critical"],
                high=counts["high"],
                medium=counts["medium"],
                low=counts["low"],
                informational=counts["informational"]
            )

            top_risks = [
                f.to_summary_dict() for f in sorted(all_findings, key=lambda x: x.risk_score, reverse=True)[:5]
            ]

            summary = ScanSummary(
                total_findings=len(all_findings),
                severity_breakdown=breakdown,
                security_score=posture_result["score"],
                top_risks=top_risks
            )

            duration = round(time.time() - start_time, 2)
            self.scan_model.findings = all_findings
            self.scan_model.correlations = correlations
            self.scan_model.attack_graph = attack_graph
            self.scan_model.summary = summary
            self.scan_model.duration_seconds = duration
            self.scan_model.completed_at = datetime.now(timezone.utc).isoformat()
            self.scan_model.status = "completed"
            self._update_progress(100, f"Assessment Complete ({duration}s)")

            logger.info(
                f"Scan {self.scan_id} finished: Security Posture {posture_result['score']}/100, "
                f"{len(all_findings)} findings detected in {duration}s."
            )
            return self.scan_model
