import json
from typing import Dict, Any, Optional
from backend.models.finding import FindingModel
from backend.ai.provider import get_ai_provider, OfflineDeterministicProvider
from backend.utils.logger import logger

class ExplainableAIEngine:
    """
    Explainable AI Engine (XAI).
    Generates evidence-grounded, auditable explanations without fake chain-of-thought.
    Breaks down Why Detected, Evidence Summary, Detection Logic, Confidence Factors,
    Observed Behavior, and Impact Assessment.
    """

    @classmethod
    async def explain(cls, finding: FindingModel) -> Dict[str, Any]:
        """
        Produces structured explainability report for a specific finding.
        Uses structured deterministic evidence as the primary ground truth.
        """
        ev = finding.evidence
        beh = ev.behavioral_changes

        # 1. Deterministic Signals
        signals = []
        if ev.status_code_changed:
            signals.append(f"HTTP status code altered from {ev.baseline_status_code} (baseline) to {ev.test_status_code} (injected)")
        if ev.error_signature:
            signals.append(f"Deterministic database/service error signature detected: '{ev.error_signature}'")
        if abs(ev.length_diff) > 50:
            signals.append(f"Significant response body variance ({ev.length_diff:+d} bytes compared to baseline)")
        if ev.response_time_changed:
            signals.append(f"Response latency variance detected ({ev.test_time_ms}ms vs {ev.baseline_time_ms}ms baseline)")
        if ev.reproducible:
            signals.append(f"Behavior consistently reproduced across {ev.reproduction_count} controlled verification attempts")
        if not signals:
            signals.append("Deterministic passive rule match on response configuration headers")

        why_detected = (
            f"The scanner compared the target baseline response with {ev.payloads_tested} controlled probe requests. "
            f"The injected probe input caused:\n" +
            "\n".join([f"• {s}" for s in signals]) +
            f"\nThese signals collectively indicate a {finding.validation_status.lower()} likelihood of {finding.type}."
        )

        # 2. Normalized Factors
        ev_factors = {
            "evidence_score": round(finding.confidence_factors.get("evidence", 80.0) / 100.0, 2),
            "behavior_score": round(finding.confidence_factors.get("behavior", 75.0) / 100.0, 2),
            "reproducibility_score": round(finding.confidence_factors.get("reproducibility", 90.0) / 100.0, 2),
            "false_positive_risk": round(max(0.01, (100.0 - finding.confidence) / 100.0), 2)
        }

        # 3. Strength Ratings
        ev_strength = "HIGH" if ev_factors["evidence_score"] >= 0.8 else ("MODERATE" if ev_factors["evidence_score"] >= 0.5 else "LOW")
        rep_strength = "HIGH" if ev_factors["reproducibility_score"] >= 0.8 else ("MODERATE" if ev_factors["reproducibility_score"] >= 0.5 else "LOW")
        beh_strength = "HIGH" if ev_factors["behavior_score"] >= 0.8 else ("MODERATE" if ev_factors["behavior_score"] >= 0.5 else "LOW")
        fp_risk_label = "LOW" if ev_factors["false_positive_risk"] <= 0.15 else ("MODERATE" if ev_factors["false_positive_risk"] <= 0.35 else "HIGH")

        confidence_narrative = (
            f"Confidence: {int(finding.confidence)}% | "
            f"Evidence strength: {ev_strength} | "
            f"Reproducibility: {rep_strength} | "
            f"Behavioral consistency: {beh_strength} | "
            f"False-positive risk: {fp_risk_label}"
        )

        observed_behavior = {
            "baseline_status": ev.baseline_status_code,
            "test_status": ev.test_status_code,
            "length_difference": ev.length_diff,
            "signature": ev.error_signature or "None",
            "reproducible": ev.reproducible,
            "snippet": ev.response.snippet if ev.response else ""
        }

        impact_assessment = (
            f"Exploitation of this {finding.severity} severity finding allows unauthorized actors to compromise "
            f"{finding.owasp.get('name', 'the system')}. Reference: {finding.cwe.get('id', 'CWE')}. "
            f"Risk Score: {finding.risk_score}/10."
        )

        deterministic_explanation = {
            "why_detected": why_detected,
            "evidence_factors": ev_factors,
            "confidence_narrative": confidence_narrative,
            "detection_logic": f"Detection Rule: {ev.detection_rule}. Evaluated baseline diff against controlled payloads.",
            "observed_behavior": observed_behavior,
            "impact_assessment": impact_assessment,
            "recommended_action": f"Apply security controls to sanitize '{finding.parameter or 'inputs'}' and enforce defense-in-depth."
        }

        # Optional LLM refinement if AI Provider is active
        provider = get_ai_provider()
        if not isinstance(provider, OfflineDeterministicProvider):
            try:
                system_prompt = (
                    "You are an auditable cybersecurity explanation engine. "
                    "Analyze the structured vulnerability evidence provided. "
                    "Do NOT fabricate evidence. Do NOT output internal chain-of-thought. "
                    "Only produce an auditable summary in JSON format matching the schema."
                )
                user_prompt = f"Vulnerability Finding: {finding.model_dump_json(exclude={'ai_explanation', 'remediation'})}"
                llm_response = await provider.generate_text(system_prompt, user_prompt)
                parsed = json.loads(llm_response.strip("```json").strip("```").strip())
                if isinstance(parsed, dict) and "why_detected" in parsed:
                    deterministic_explanation.update(parsed)
            except Exception as e:
                logger.debug(f"LLM explanation fallback to deterministic rules: {e}")

        return deterministic_explanation
