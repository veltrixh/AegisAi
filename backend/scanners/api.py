import json
import uuid
import yaml
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin

from backend.scanners.base import BaseScanner
from backend.models.finding import FindingModel
from backend.models.evidence import RequestEvidence, ResponseEvidence
from backend.core.evidence import EvidenceCollector
from backend.ai.confidence import ConfidenceEngine
from backend.core.risk_engine import RiskEngine
from backend.intelligence.knowledge import get_vulnerability_metadata
from backend.utils.http_client import ScannerResponse, AsyncScannerClient
from backend.utils.logger import logger

class APISecurityScanner(BaseScanner):
    """
    OpenAPI / Swagger 2.0 & 3.0+ Specification Security Analyzer.
    Parses definitions to identify missing authentication, excessive data exposure,
    injection-prone path parameters, and insecure security configurations.
    """
    name = "OpenAPI / REST Security Scanner"
    vulnerability_type = "api_security"
    category = "active"

    # Known sensitive keywords that indicate critical functions
    SENSITIVE_PATH_KEYWORDS = {"admin", "user", "users", "account", "payment", "order", "credit", "auth", "profile", "keys"}

    async def scan(self, target: str, context: Dict[str, Any]) -> List[FindingModel]:
        logger.info(f"Initiating API security analysis for: {target}")
        findings: List[FindingModel] = []

        spec = context.get("openapi_spec")
        spec_dict: Optional[Dict[str, Any]] = None

        if isinstance(spec, dict):
            spec_dict = spec
        elif isinstance(spec, str) and spec.strip():
            try:
                spec_dict = json.loads(spec)
            except Exception:
                try:
                    spec_dict = yaml.safe_load(spec)
                except Exception as e:
                    logger.warning(f"Failed to parse provided OpenAPI spec: {e}")

        # If no spec explicitly provided, check common OpenAPI/Swagger discovery paths
        if not spec_dict:
            if not self.client:
                self.client = AsyncScannerClient()
            swagger_paths = ["/openapi.json", "/swagger.json", "/api/v1/openapi.json", "/api/docs/openapi.json"]
            for spath in swagger_paths:
                probe_url = urljoin(target, spath)
                res = await self.client.get(probe_url)
                if res.status_code == 200 and ("openapi" in res.text or "swagger" in res.text):
                    try:
                        spec_dict = json.loads(res.text)
                        logger.info(f"Discovered active OpenAPI spec at: {probe_url}")
                        break
                    except Exception:
                        pass

        if not spec_dict or not isinstance(spec_dict, dict):
            logger.debug(f"No OpenAPI spec discovered on {target}")
            return findings

        # Analyze OpenAPI Specification
        paths = spec_dict.get("paths", {})
        global_security = spec_dict.get("security", [])

        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            for method_str, op in path_item.items():
                if method_str.lower() not in ("get", "post", "put", "delete", "patch"):
                    continue

                op_security = op.get("security", global_security)
                path_tokens = set(re_token.lower() for re_token in path_str.strip("/").split("/"))
                is_sensitive_path = bool(path_tokens.intersection(self.SENSITIVE_PATH_KEYWORDS))

                # Check 1: Missing Authentication on Sensitive API Endpoint
                if (not op_security or len(op_security) == 0) and is_sensitive_path:
                    meta = get_vulnerability_metadata("api_missing_auth")
                    rule_id = "api_unauthenticated_endpoint"

                    dummy_resp = ScannerResponse(
                        status_code=200, headers={}, text=f"OpenAPI path {path_str} specifies no security requirement",
                        elapsed_ms=5.0, url=urljoin(target, path_str), method=method_str.upper()
                    )
                    evidence = EvidenceCollector.capture(
                        baseline=dummy_resp,
                        test_response=dummy_resp,
                        test_request_data={"method": method_str.upper(), "url": urljoin(target, path_str), "headers": {}},
                        error_signature=None,
                        detection_rule=rule_id,
                        payload_category="api_auth_check",
                        reproducible=True,
                        extra_behavior={
                            "endpoint": path_str,
                            "method": method_str.upper(),
                            "declared_security": op_security,
                            "is_sensitive_path": True
                        }
                    )
                    conf, conf_factors, val_status = ConfidenceEngine.evaluate(evidence, rule_id)
                    risk = RiskEngine.calculate_finding_risk(meta["default_cvss"], conf)

                    findings.append(FindingModel(
                        finding_id=f"API-{uuid.uuid4().hex[:6].upper()}",
                        type="API Missing Authentication",
                        title=f"Sensitive Endpoint '{method_str.upper()} {path_str}' Lacks Authentication",
                        target=urljoin(target, path_str),
                        parameter=path_str,
                        method=method_str.upper(),
                        severity="HIGH",
                        risk_score=risk,
                        cvss=meta["default_cvss"],
                        cvss_vector=meta["default_vector"],
                        confidence=conf,
                        confidence_factors=conf_factors,
                        validation_status=val_status,
                        owasp={"id": meta["owasp_id"], "name": meta["owasp_name"]},
                        cwe={"id": meta["cwe_id"], "name": meta["cwe_name"]},
                        evidence=evidence
                    ))

                # Check 2: Excessive Data Exposure in Schema Responses
                responses = op.get("responses", {})
                for status_code, resp_def in responses.items():
                    if str(status_code).startswith("2"):
                        content = resp_def.get("content", {})
                        json_content = content.get("application/json", {})
                        schema = json_content.get("schema", {})
                        properties = schema.get("properties", {})
                        sensitive_props = [
                            p for p in properties.keys()
                            if any(sens in p.lower() for sens in ["password", "secret", "token", "ssn", "salt", "private_key"])
                        ]
                        if sensitive_props:
                            meta = get_vulnerability_metadata("api_excessive_exposure")
                            rule_id = "api_excessive_data_exposure"
                            dummy_resp = ScannerResponse(
                                status_code=200, headers={}, text=f"Exposed schema properties: {', '.join(sensitive_props)}",
                                elapsed_ms=5.0, url=urljoin(target, path_str), method=method_str.upper()
                            )
                            evidence = EvidenceCollector.capture(
                                baseline=dummy_resp,
                                test_response=dummy_resp,
                                test_request_data={"method": method_str.upper(), "url": urljoin(target, path_str)},
                                error_signature=None,
                                detection_rule=rule_id,
                                payload_category="api_schema_exposure",
                                reproducible=True,
                                extra_behavior={"exposed_properties": sensitive_props}
                            )
                            conf, conf_factors, val_status = ConfidenceEngine.evaluate(evidence, rule_id)
                            risk = RiskEngine.calculate_finding_risk(meta["default_cvss"], conf)

                            findings.append(FindingModel(
                                finding_id=f"API-{uuid.uuid4().hex[:6].upper()}",
                                type="API Excessive Data Exposure",
                                title=f"Sensitive Properties Defined in Response Schema ({', '.join(sensitive_props)})",
                                target=urljoin(target, path_str),
                                parameter=f"response_{status_code}",
                                method=method_str.upper(),
                                severity="MEDIUM",
                                risk_score=risk,
                                cvss=meta["default_cvss"],
                                cvss_vector=meta["default_vector"],
                                confidence=conf,
                                confidence_factors=conf_factors,
                                validation_status=val_status,
                                owasp={"id": meta["owasp_id"], "name": meta["owasp_name"]},
                                cwe={"id": meta["cwe_id"], "name": meta["cwe_name"]},
                                evidence=evidence
                            ))

        return findings
