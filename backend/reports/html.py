from typing import Dict, Any
from jinja2 import Template
from backend.models.scan import ScanModel

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report — {{ scan.target_url }}</title>
    <style>
        :root {
            --bg-dark: #0f172a;
            --card-bg: #1e293b;
            --border-color: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --crit: #ef4444;
            --high: #f97316;
            --med: #eab308;
            --low: #3b82f6;
            --info: #64748b;
            --success: #10b981;
            --accent: #6366f1;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            line-height: 1.5;
            padding: 30px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 { font-size: 26px; font-weight: 700; color: #fff; }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
        }
        .badge-CRITICAL { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
        .badge-HIGH { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }
        .badge-MEDIUM { background: rgba(234, 179, 8, 0.2); color: #fde047; border: 1px solid #eab308; }
        .badge-LOW { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }
        .badge-INFO { background: rgba(100, 116, 139, 0.2); color: #94a3b8; border: 1px solid #64748b; }
        
        .grid-score {
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        .card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 24px;
        }
        .score-circle {
            text-align: center;
        }
        .score-val {
            font-size: 64px;
            font-weight: 900;
            color: {% if scan.summary.security_score >= 80 %}#10b981{% elif scan.summary.security_score >= 60 %}#eab308{% else %}#ef4444{% endif %};
        }
        .score-label { color: var(--text-muted); font-size: 14px; text-transform: uppercase; letter-spacing: 1px; }
        
        .breakdown-row {
            display: flex;
            justify-content: space-around;
            text-align: center;
            margin-top: 15px;
        }
        .breakdown-item h3 { font-size: 24px; font-weight: 700; }
        .breakdown-item p { font-size: 12px; color: var(--text-muted); text-transform: uppercase; }
        
        .finding-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }
        .finding-title { font-size: 18px; font-weight: 600; }
        .meta-pill {
            font-size: 12px;
            background: #0f172a;
            padding: 4px 8px;
            border-radius: 4px;
            border: 1px solid var(--border-color);
            margin-right: 8px;
        }
        .code-box {
            background: #090d16;
            border: 1px solid #1e293b;
            border-radius: 6px;
            padding: 12px;
            font-family: "Courier New", Courier, monospace;
            font-size: 12px;
            color: #38bdf8;
            overflow-x: auto;
            margin-top: 8px;
            white-space: pre-wrap;
        }
        .evidence-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin: 12px 0;
            font-size: 13px;
        }
        .remediation-box {
            background: rgba(16, 185, 129, 0.05);
            border-left: 4px solid var(--success);
            padding: 12px;
            margin-top: 12px;
            font-size: 13px;
        }
        .attack-chain-box {
            background: rgba(99, 102, 241, 0.08);
            border: 1px solid rgba(99, 102, 241, 0.3);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 15px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>AEGIS AI-Vuln-Scanner Assessment Report</h1>
                <p style="color: var(--text-muted); margin-top: 4px;">Target: <strong>{{ scan.target_url }}</strong> | Profile: {{ scan.profile|upper }}</p>
            </div>
            <div style="text-align: right; color: var(--text-muted); font-size: 13px;">
                <p>Scan ID: {{ scan.id }}</p>
                <p>Date: {{ scan.completed_at or scan.created_at }}</p>
                <p>Duration: {{ scan.duration_seconds }}s</p>
            </div>
        </div>

        <div class="grid-score">
            <div class="card score-circle">
                <div class="score-label">Security Posture Score</div>
                <div class="score-val">{{ scan.summary.security_score }}</div>
                <div style="color: var(--text-muted); font-size: 13px;">Scale: 0 (Critical) — 100 (Secure)</div>
            </div>
            <div class="card">
                <h2 style="font-size: 16px; margin-bottom: 15px;">Severity Breakdown</h2>
                <div class="breakdown-row">
                    <div class="breakdown-item">
                        <h3 style="color: var(--crit);">{{ scan.summary.severity_breakdown.critical }}</h3>
                        <p>Critical</p>
                    </div>
                    <div class="breakdown-item">
                        <h3 style="color: var(--high);">{{ scan.summary.severity_breakdown.high }}</h3>
                        <p>High</p>
                    </div>
                    <div class="breakdown-item">
                        <h3 style="color: var(--med);">{{ scan.summary.severity_breakdown.medium }}</h3>
                        <p>Medium</p>
                    </div>
                    <div class="breakdown-item">
                        <h3 style="color: var(--low);">{{ scan.summary.severity_breakdown.low }}</h3>
                        <p>Low</p>
                    </div>
                    <div class="breakdown-item">
                        <h3 style="color: var(--info);">{{ scan.summary.severity_breakdown.informational }}</h3>
                        <p>Info</p>
                    </div>
                </div>
                <p style="margin-top: 20px; font-size: 13px; color: var(--text-muted);">
                    Total Findings: <strong>{{ scan.summary.total_findings }}</strong> | 
                    Attack Chains Identified: <strong>{{ scan.attack_graph.chains|length }}</strong>
                </p>
            </div>
        </div>

        {% if scan.attack_graph.chains %}
        <div class="card" style="margin-bottom: 30px;">
            <h2 style="font-size: 18px; margin-bottom: 15px;">Synthesized Attack Chains & Paths</h2>
            {% for chain in scan.attack_graph.chains %}
            <div class="attack-chain-box">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <strong>{{ chain.name }}</strong>
                    <span class="badge badge-{{ chain.impact_level }}">{{ chain.impact_level }} Risk ({{ chain.cumulative_risk }}/10)</span>
                </div>
                <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 8px;">{{ chain.description }}</p>
                <div style="font-size: 12px; color: #a5b4fc; font-family: monospace;">
                    Path: {{ chain.path_nodes | join(' &rarr; ') }}
                </div>
            </div>
            {% endfor %}
        </div>
        {% endif %}

        <h2 style="font-size: 20px; margin-bottom: 20px;">Vulnerability Findings & Evidence</h2>
        {% for finding in scan.findings %}
        <div class="finding-card">
            <div class="finding-header">
                <div>
                    <span class="badge badge-{{ finding.severity }}">{{ finding.severity }}</span>
                    <strong class="finding-title" style="margin-left: 10px;">{{ finding.title }}</strong>
                </div>
                <div>
                    <span class="meta-pill">Risk: {{ finding.risk_score }}/10</span>
                    <span class="meta-pill">Confidence: {{ finding.confidence }}% ({{ finding.validation_status }})</span>
                </div>
            </div>

            <div style="margin-bottom: 10px; font-size: 13px; color: var(--text-muted);">
                Endpoint: <code>{{ finding.target }}</code> | 
                Param: <code>{{ finding.parameter or 'N/A' }}</code> | 
                OWASP: <strong>{{ finding.owasp.id }}</strong> | 
                CWE: <strong>{{ finding.cwe.id }}</strong> (CVSS {{ finding.cvss }})
            </div>

            {% if finding.ai_explanation %}
            <div style="background: rgba(255,255,255,0.03); padding: 12px; border-radius: 6px; font-size: 13px; margin: 10px 0;">
                <strong style="color: #cbd5e1;">Why Detected:</strong>
                <p style="margin-top: 4px; white-space: pre-line;">{{ finding.ai_explanation.why_detected }}</p>
            </div>
            {% endif %}

            <div class="evidence-grid">
                <div>
                    <strong>Deterministic Evidence:</strong>
                    <ul style="margin-left: 18px; margin-top: 6px; color: var(--text-muted);">
                        <li>Baseline Length: {{ finding.evidence.baseline_response_length }}B vs Test: {{ finding.evidence.test_response_length }}B (Δ {{ finding.evidence.length_diff }}B)</li>
                        <li>Status Changed: {{ finding.evidence.status_code_changed }} (Baseline: {{ finding.evidence.baseline_status_code }} vs Test: {{ finding.evidence.test_status_code }})</li>
                        <li>Reproducibility: {{ finding.evidence.reproducible }} (Tested {{ finding.evidence.payloads_tested }}, Verified {{ finding.evidence.reproduction_count }}x)</li>
                        {% if finding.evidence.error_signature %}
                        <li style="color: #f87171;">Signature Caught: {{ finding.evidence.error_signature }}</li>
                        {% endif %}
                    </ul>
                </div>
                <div>
                    <strong>Sanitized Payload Snippet:</strong>
                    <div class="code-box">{{ finding.evidence.response.snippet or "No snippet captured" }}</div>
                </div>
            </div>

            {% if finding.remediation %}
            <div class="remediation-box">
                <strong style="color: #34d399;">Remediation Recommendation:</strong>
                <p style="margin: 4px 0 8px 0;">{{ finding.remediation.recommendation }}</p>
                <strong>Verification Procedure:</strong>
                <p style="margin-top: 4px; color: var(--text-muted);">{{ finding.remediation.verification }}</p>
            </div>
            {% endif %}
        </div>
        {% endfor %}

        <div style="text-align: center; color: var(--text-muted); font-size: 12px; margin-top: 40px; border-top: 1px solid var(--border-color); padding-top: 20px;">
            Generated by AEGIS AI-Vuln-Scanner v2.0 &bull; Deterministic &bull; Explainable &bull; Evidence-Grounded
        </div>
    </div>
</body>
</html>
"""

class HtmlReportExporter:
    """Renders standalone HTML reports with rich dark-mode security console formatting."""

    @classmethod
    def render(cls, scan: ScanModel) -> str:
        template = Template(HTML_TEMPLATE)
        return template.render(scan=scan)
