import re
import uuid
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from backend.scanners.base import BaseScanner
from backend.models.finding import FindingModel
from backend.core.evidence import EvidenceCollector
from backend.ai.confidence import ConfidenceEngine
from backend.core.risk_engine import RiskEngine
from backend.intelligence.knowledge import get_vulnerability_metadata
from backend.utils.http_client import ScannerResponse, AsyncScannerClient
from backend.utils.logger import logger

# Comprehensive deterministic SQL error signatures
SQL_ERROR_PATTERNS = {
    "mysql": [
        re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
        re.compile(r"warning: mysql_", re.IGNORECASE),
        re.compile(r"check the manual that corresponds to your (mysql|mariadb) server version", re.IGNORECASE),
    ],
    "postgresql": [
        re.compile(r"pg_query\(\): query failed", re.IGNORECASE),
        re.compile(r"error: syntax error at or near", re.IGNORECASE),
        re.compile(r"psycopg2\.errors\.", re.IGNORECASE),
    ],
    "sqlite": [
        re.compile(r"sqlite3\.operationalerror", re.IGNORECASE),
        re.compile(r"unrecognized token:", re.IGNORECASE),
        re.compile(r"sqlite_error", re.IGNORECASE),
        re.compile(r"near \".*\": syntax error", re.IGNORECASE),
    ],
    "mssql": [
        re.compile(r"unclosed quotation mark after the character string", re.IGNORECASE),
        re.compile(r"microsoft ole db provider for sql server", re.IGNORECASE),
        re.compile(r"syntax error in string in query expression", re.IGNORECASE),
    ],
    "oracle": [
        re.compile(r"ora-[0-9]{4,5}", re.IGNORECASE),
        re.compile(r"oracle error", re.IGNORECASE),
    ]
}

# Controlled test probes (error and boolean verification)
SQLI_PAYLOADS = [
    {"payload": "' OR '1'='1", "type": "error_boolean", "quote": "'"},
    {"payload": "1' AND 1=1 --", "type": "comment_injection", "quote": "'"},
    {"payload": "\" OR \"1\"=\"1", "type": "double_quote_boolean", "quote": "\""},
    {"payload": "1' OR '1'='2", "type": "boolean_false", "quote": "'"},
]

class SQLInjectionScanner(BaseScanner):
    """
    Deterministic SQL Injection Scanner.
    Executes controlled error-based and boolean-based probes against parameters.
    Captures baseline comparison, status diffs, error signatures, and verifies reproducibility.
    """
    name = "Deterministic SQL Injection Engine"
    vulnerability_type = "sql_injection"
    category = "active"

    async def scan(self, target: str, context: Dict[str, Any]) -> List[FindingModel]:
        logger.info(f"Scanning target for SQL Injection: {target}")
        findings: List[FindingModel] = []

        if not self.client:
            self.client = AsyncScannerClient()

        baseline: ScannerResponse = context.get("baseline")
        if not baseline:
            baseline = await self.client.get(target)

        # Discover parameters
        params_to_test = context.get("discovered_params", [])
        if not params_to_test:
            params_to_test = ["id", "user", "item", "query", "search", "page", "cat"]

        tested_params = set()

        for param in params_to_test:
            if param in tested_params:
                continue
            tested_params.add(param)

            # Test each payload
            matched_signature = None
            successful_payloads = 0
            best_test_response: Optional[ScannerResponse] = None
            best_payload_used = ""
            rule_matched = "sqli_syntax_error"

            for probe in SQLI_PAYLOADS:
                payload = probe["payload"]
                test_url = self._inject_param(target, param, payload)
                test_res = await self.client.get(test_url)

                # Check SQL errors in response
                detected_db, matched_regex = self._detect_sql_error(test_res.text)
                if detected_db:
                    matched_signature = f"{detected_db} ({matched_regex})"
                    successful_payloads += 1
                    best_test_response = test_res
                    best_payload_used = payload
                    rule_matched = "sqli_syntax_error"
                    break
                elif (
                    test_res.status_code == 500 and baseline.status_code != 500
                    and abs(test_res.length - baseline.length) > 100
                ):
                    # Internal server error triggered by syntax probe
                    successful_payloads += 1
                    matched_signature = "Internal Server Error triggered by SQL quote syntax"
                    best_test_response = test_res
                    best_payload_used = payload
                    rule_matched = "sqli_boolean_diff"

            # If evidence detected, verify reproducibility
            if successful_payloads > 0 and best_test_response:
                repro_count = 0
                for _ in range(2):
                    repro_url = self._inject_param(target, param, best_payload_used)
                    repro_res = await self.client.get(repro_url)
                    if (
                        (matched_signature and self._detect_sql_error(repro_res.text)[0]) or
                        (repro_res.status_code == best_test_response.status_code)
                    ):
                        repro_count += 1

                reproducible = repro_count >= 1

                evidence = EvidenceCollector.capture(
                    baseline=baseline,
                    test_response=best_test_response,
                    test_request_data={
                        "method": "GET",
                        "url": self._inject_param(target, param, best_payload_used),
                        "params": {param: best_payload_used}
                    },
                    error_signature=matched_signature,
                    detection_rule=rule_matched,
                    payload_category="sql_injection",
                    payloads_tested=len(SQLI_PAYLOADS),
                    successful_payloads=successful_payloads,
                    reproduction_count=repro_count + 1,
                    reproducible=reproducible,
                    snippet_pattern=matched_signature.split()[0] if matched_signature else None,
                    extra_behavior={
                        "injected_parameter": param,
                        "test_payload": best_payload_used,
                        "error_signature": matched_signature
                    }
                )

                meta = get_vulnerability_metadata("sql_injection")
                conf, conf_factors, val_status = ConfidenceEngine.evaluate(evidence, rule_matched)
                risk = RiskEngine.calculate_finding_risk(meta["default_cvss"], conf)

                finding = FindingModel(
                    finding_id=f"SQLI-{uuid.uuid4().hex[:6].upper()}",
                    type="SQL Injection",
                    title=f"SQL Injection in parameter '{param}'",
                    target=target,
                    parameter=param,
                    method="GET",
                    severity="CRITICAL" if risk >= 9.0 else "HIGH",
                    risk_score=risk,
                    cvss=meta["default_cvss"],
                    cvss_vector=meta["default_vector"],
                    confidence=conf,
                    confidence_factors=conf_factors,
                    validation_status=val_status,
                    owasp={"id": meta["owasp_id"], "name": meta["owasp_name"]},
                    cwe={"id": meta["cwe_id"], "name": meta["cwe_name"]},
                    evidence=evidence
                )
                findings.append(finding)
                logger.info(f"Confirmed SQL Injection in '{param}' with confidence {conf}% (status: {val_status})")

        return findings

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [value]
        new_query = urlencode(qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    def _detect_sql_error(self, text: str) -> (Optional[str], Optional[str]):
        if not text:
            return None, None
        for db, patterns in SQL_ERROR_PATTERNS.items():
            for p in patterns:
                m = p.search(text)
                if m:
                    return db, m.group(0)
        return None, None
