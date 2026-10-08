import json
from typing import Dict, Any, List
from backend.models.scan import ScanModel
from backend.models.finding import FindingModel

def _severity_to_sarif_level(severity: str) -> str:
    sev = severity.upper()
    if sev in ("CRITICAL", "HIGH"):
        return "error"
    elif sev == "MEDIUM":
        return "warning"
    elif sev == "LOW":
        return "note"
    return "none"

class SarifExporter:
    """
    Exports Scan findings into standardized OASIS SARIF 2.1.0 format
    compatible with GitHub Advanced Security, GitLab SAST/DAST, and CI/CD gates.
    """

    @classmethod
    def export(cls, scan: ScanModel) -> Dict[str, Any]:
        rules: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        for f in scan.findings:
            rule_id = f.cwe.get("id") or f.type.replace(" ", "_").upper()
            rem_rec = f.remediation.get("recommendation", "Apply defensive validation") if f.remediation else "Apply defensive validation"
            why_det = f.ai_explanation.get("why_detected", "") if f.ai_explanation else ""

            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f.type.replace(" ", ""),
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.cwe.get("name", f.title)},
                    "help": {
                        "text": f"Remediation: {rem_rec}",
                        "markdown": f"### Remediation\n{rem_rec}\n\n**OWASP**: {f.owasp.get('id', '')} - {f.owasp.get('name', '')}\n**CWE**: {f.cwe.get('id', '')}"
                    },
                    "properties": {
                        "tags": ["security", f.owasp.get("id", "security"), f.cwe.get("id", "security")],
                        "security-severity": str(f.cvss)
                    }
                }

            level = _severity_to_sarif_level(f.severity)
            message_text = (
                f"{f.title} (Severity: {f.severity}, Risk: {f.risk_score}/10, Confidence: {f.confidence}%). "
                f"Validation Status: {f.validation_status}."
            )

            result_item = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": message_text,
                    "markdown": f"**{f.title}**\n\n{why_det}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.target,
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": 1,
                                "startColumn": 1
                            }
                        }
                    }
                ],
                "properties": {
                    "findingId": f.finding_id,
                    "cvss": f.cvss,
                    "riskScore": f.risk_score,
                    "confidence": f.confidence,
                    "validationStatus": f.validation_status,
                    "parameter": f.parameter,
                    "method": f.method
                }
            }
            results.append(result_item)

        sarif_log = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AEGIS AI-Vuln-Scanner",
                            "version": "2.0.0",
                            "informationUri": "https://github.com/4xyy/AI-Vuln-Scanner",
                            "rules": list(rules.values())
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": scan.completed_at or scan.created_at
                        }
                    ],
                    "results": results
                }
            ]
        }
        return sarif_log

    @classmethod
    def export_json_string(cls, scan: ScanModel) -> str:
        return json.dumps(cls.export(scan), indent=2)
