import pytest
from backend.models.finding import FindingModel
from backend.models.evidence import EvidenceModel
from backend.core.correlation import VulnerabilityCorrelationEngine
from backend.core.attack_graph import AttackPathEngine

def test_vulnerability_correlation_xss_cookies():
    ev_xss = EvidenceModel(reproducible=True)
    f_xss = FindingModel(
        finding_id="XSS-001", type="Cross-Site Scripting (Reflected)", title="XSS in q",
        target="http://example.com/search", parameter="q", severity="HIGH",
        risk_score=7.8, cvss=7.2, confidence=92.0, evidence=ev_xss
    )
    ev_hdr = EvidenceModel(reproducible=True, behavioral_changes={"cookie_flaws": ["Missing HttpOnly"]})
    f_hdr = FindingModel(
        finding_id="CK-001", type="Insecure Cookie Attributes", title="Missing HttpOnly",
        target="http://example.com", parameter="Set-Cookie", severity="MEDIUM",
        risk_score=5.0, cvss=5.0, confidence=99.0, evidence=ev_hdr
    )

    correlations = VulnerabilityCorrelationEngine.correlate([f_xss, f_hdr])
    assert len(correlations) >= 1
    c = correlations[0]
    assert c.relationship_type == "BROWSER_SESSION_COMPROMISE_SYNERGY"
    assert "XSS-001" in c.findings_involved
    assert c.compounded_risk_score >= 9.0

def test_attack_path_graph_generation():
    ev = EvidenceModel(reproducible=True, error_signature="syntax error")
    f_sqli = FindingModel(
        finding_id="SQLI-001", type="SQL Injection", title="SQL Injection in id",
        target="http://example.com/products", parameter="id", severity="CRITICAL",
        risk_score=9.4, cvss=8.8, confidence=95.0, evidence=ev
    )
    graph = AttackPathEngine.generate("http://example.com", [f_sqli])
    assert len(graph.nodes) >= 4  # internet, webapp, endpoint, vector/vuln, asset
    assert len(graph.edges) >= 3
    assert len(graph.chains) == 1
    assert graph.risk == 9.4
    chain = graph.chains[0]
    assert "asset_database" in chain.path_nodes[-1]
