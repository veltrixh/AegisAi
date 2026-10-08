import json
from typing import Dict, Any, List, Optional
from backend.models.scan import ScanModel
from backend.models.finding import FindingModel
from backend.ai.provider import get_ai_provider, OfflineDeterministicProvider
from backend.utils.logger import logger

class AISecurityAnalyst:
    """
    Evidence-grounded conversational AI Security Analyst.
    Enforces strict truthfulness: Never fabricates evidence.
    Clearly distinguishes:
      [OBSERVED]: Verified deterministic facts from scan evidence
      [INFERRED]: Analytical deductions based on threat modeling
      [RECOMMENDED]: Actionable architectural & code remediation
    """

    @classmethod
    async def ask(
        cls,
        question: str,
        scan: ScanModel,
        selected_finding: Optional[FindingModel] = None,
        previous_scan: Optional[ScanModel] = None
    ) -> Dict[str, Any]:
        question_lower = question.lower()
        findings = scan.findings
        correlations = scan.correlations
        top_risks = sorted(findings, key=lambda x: x.risk_score, reverse=True)[:3]

        # 1. Fallback / Deterministic Answer Logic
        observed_points = []
        inferred_points = []
        recommended_points = []

        if "top 3" in question_lower or "top risks" in question_lower or "which" in question_lower and "first" in question_lower:
            observed_points.append(
                f"Scanned {scan.target_url} and identified {len(findings)} total findings. "
                f"The highest calculated risk findings are: " +
                ", ".join([f"{f.type} (Risk: {f.risk_score}/10, Severity: {f.severity})" for f in top_risks])
            )
            if top_risks:
                highest = top_risks[0]
                inferred_points.append(
                    f"'{highest.title}' poses the most immediate exploitability vector because its detection confidence is "
                    f"{highest.confidence}% with CVSS score {highest.cvss}."
                )
                recommended_points.append(
                    f"Prioritize remediation on '{highest.title}' ({highest.target}) before lower severity configuration items. "
                    f"Verify using the scanner's reproduction rule '{highest.evidence.detection_rule}'."
                )

        elif "false positive" in question_lower:
            target_finding = selected_finding or (top_risks[0] if top_risks else None)
            if target_finding:
                ev = target_finding.evidence
                observed_points.append(
                    f"Finding '{target_finding.title}' has Validation Status '{target_finding.validation_status}' with "
                    f"Confidence {target_finding.confidence}%. Tested {ev.payloads_tested} payloads, reproduced {ev.reproduction_count} times."
                )
                if ev.error_signature:
                    observed_points.append(f"Direct error signature caught: '{ev.error_signature}'.")
                inferred_points.append(
                    "Given the reproducible behavioral response difference and signature match, the probability of a false positive is LOW."
                    if target_finding.confidence >= 80 else
                    "This finding has moderate confidence; behavioral anomaly was noted, but manual verification is suggested."
                )
                recommended_points.append(
                    f"Inspect the raw HTTP evidence snippet in the Finding Drawer and verify if parameter '{target_finding.parameter}' "
                    "accepts controlled syntax."
                )
            else:
                observed_points.append("No specific finding selected to evaluate false positive probability.")

        elif "connected" in question_lower or "correlation" in question_lower or "attack path" in question_lower:
            if correlations:
                for c in correlations:
                    observed_points.append(f"Correlation [{c.relationship_type}] detected involving {len(c.findings_involved)} findings.")
                    inferred_points.append(f"Attack synergy: {c.reason}")
                recommended_points.append(
                    "Remediating the root injection vulnerability breaks the attack chain even if defensive headers remain unchanged."
                )
            else:
                observed_points.append("No multi-finding compound correlation chains were detected in this scan.")
                inferred_points.append("Current findings appear isolated at this perimeter layer.")
                recommended_points.append("Remediate individual findings based on severity ranking.")

        elif "compare" in question_lower or "previous" in question_lower or "changed" in question_lower:
            if previous_scan:
                score_before = previous_scan.summary.security_score
                score_after = scan.summary.security_score
                diff = score_after - score_before
                observed_points.append(
                    f"Previous Scan Score: {score_before}/100. Current Scan Score: {score_after}/100. Delta: {diff:+0.1f}."
                )
                inferred_points.append(
                    "Security posture has improved." if diff > 0 else ("Security posture regressed." if diff < 0 else "Posture unchanged.")
                )
                recommended_points.append("Maintain regression tests in CI/CD pipeline to protect remediated endpoints.")
            else:
                observed_points.append("No prior baseline scan was supplied for comparison.")
                inferred_points.append("Comparison requires two distinct scan IDs.")
                recommended_points.append("Use the Scan Comparison view to compare Scan A against Scan B.")

        else:
            target_finding = selected_finding or (top_risks[0] if top_risks else None)
            if target_finding:
                observed_points.append(
                    f"Finding: {target_finding.title} | Severity: {target_finding.severity} | Risk: {target_finding.risk_score}/10 | "
                    f"Confidence: {target_finding.confidence}% ({target_finding.validation_status})."
                )
                inferred_points.append(
                    f"Vulnerability maps to {target_finding.owasp.get('id', 'OWASP')} and {target_finding.cwe.get('id', 'CWE')}. "
                    f"Permits unauthorized interaction with {target_finding.parameter or 'endpoint'}."
                )
                recommended_points.append(
                    f"Implement input sanitization and parameterization on {target_finding.target}. Verify with the evidence verification rule."
                )
            else:
                observed_points.append(f"Target: {scan.target_url} | Security Posture Score: {scan.summary.security_score}/100.")
                inferred_points.append("System scanned with profile: " + scan.profile)
                recommended_points.append("Select an individual finding or ask about top risks to dive deeper.")

        # Default fallback structure
        analyst_response = {
            "question": question,
            "observed": observed_points,
            "inferred": inferred_points,
            "recommended": recommended_points,
            "summary": (
                f"**[OBSERVED]**\n" + "\n".join([f"• {x}" for x in observed_points]) + "\n\n" +
                f"**[INFERRED]**\n" + "\n".join([f"• {x}" for x in inferred_points]) + "\n\n" +
                f"**[RECOMMENDED]**\n" + "\n".join([f"• {x}" for x in recommended_points])
            )
        }

        # If LLM Provider is available, enrich the response with strict ground truth prompt
        provider = get_ai_provider()
        if not isinstance(provider, OfflineDeterministicProvider):
            try:
                system_prompt = (
                    "You are a Senior AI Security Analyst. "
                    "You must NEVER fabricate evidence or claim a vulnerability is definitely present without evidence. "
                    "Use only the provided scan findings and security context. "
                    "Structure your answer strictly into three sections: "
                    "[OBSERVED] (verified evidence facts), "
                    "[INFERRED] (threat deductions), and "
                    "[RECOMMENDED] (actionable fixes). "
                    "Output JSON with keys 'observed' (list), 'inferred' (list), 'recommended' (list), 'summary' (str)."
                )
                scan_context = {
                    "target": scan.target_url,
                    "score": scan.summary.security_score,
                    "findings_count": len(findings),
                    "top_risks": [f.to_summary_dict() for f in top_risks],
                    "selected_finding": selected_finding.to_summary_dict() if selected_finding else None,
                    "correlations": [c.model_dump() for c in correlations]
                }
                user_prompt = f"Question: {question}\nContext: {json.dumps(scan_context)}"
                raw_llm = await provider.generate_text(system_prompt, user_prompt)
                parsed = json.loads(raw_llm.strip("```json").strip("```").strip())
                if isinstance(parsed, dict) and "observed" in parsed:
                    analyst_response.update(parsed)
            except Exception as e:
                logger.debug(f"AI Analyst LLM fallback to deterministic logic: {e}")

        return analyst_response
