import io
from typing import Optional
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from backend.models.scan import ScanModel

class PdfReportExporter:
    """Generates professional executive PDF security assessment reports."""

    @classmethod
    def render_bytes(cls, scan: ScanModel) -> bytes:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )
        story = []
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold"
        )
        subtitle_style = ParagraphStyle(
            "DocSubtitle",
            parent=styles["Normal"],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#475569")
        )
        heading_style = ParagraphStyle(
            "SectionHeading",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1e293b"),
            fontName="Helvetica-Bold",
            spaceBefore=15,
            spaceAfter=8
        )
        body_style = ParagraphStyle(
            "DocBody",
            parent=styles["Normal"],
            fontSize=10,
            leading=13,
            textColor=colors.HexColor("#334155")
        )

        # Header
        story.append(Paragraph("AEGIS AI-Vuln-Scanner Assessment Report", title_style))
        story.append(Spacer(1, 4))
        story.append(Paragraph(f"Target: <b>{scan.target_url}</b> | Profile: <b>{scan.profile.upper()}</b> | Scan ID: {scan.id}", subtitle_style))
        story.append(Paragraph(f"Generated: {scan.completed_at or scan.created_at} | Duration: {scan.duration_seconds}s", subtitle_style))
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#6366f1"), spaceAfter=15))

        # Executive Summary Table
        sev = scan.summary.severity_breakdown
        summary_data = [
            ["Security Posture Score", f"{scan.summary.security_score} / 100", "Total Findings", str(scan.summary.total_findings)],
            ["Critical Severity", str(sev.critical), "High Severity", str(sev.high)],
            ["Medium Severity", str(sev.medium), "Low Severity", str(sev.low)],
        ]
        t = Table(summary_data, colWidths=[140, 120, 140, 120])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1e293b")),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#94a3b8")),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(t)
        story.append(Spacer(1, 15))

        # Findings Summary Table
        story.append(Paragraph("Vulnerability Findings Summary", heading_style))
        findings_table_data = [["Type", "Target", "Severity", "Risk", "Confidence", "OWASP"]]
        for f in scan.findings:
            findings_table_data.append([
                Paragraph(f.type, body_style),
                Paragraph(f.target[:35] + ("..." if len(f.target) > 35 else ""), body_style),
                f.severity,
                f"{f.risk_score}/10",
                f"{f.confidence}%",
                f.owasp.get("id", "N/A")
            ])

        ft = Table(findings_table_data, colWidths=[110, 170, 60, 55, 65, 60])
        ft.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(ft)
        story.append(Spacer(1, 20))

        # Detailed Findings Section
        story.append(Paragraph("Detailed Evidence & Remediation", heading_style))
        for f in scan.findings:
            story.append(Paragraph(f"<b>[{f.severity}] {f.title}</b>", ParagraphStyle("FTitle", parent=styles["Heading3"], fontSize=11, textColor=colors.HexColor("#0f172a"))))
            story.append(Paragraph(f"Endpoint: {f.target} | Parameter: {f.parameter or 'N/A'} | Status: {f.validation_status} ({f.confidence}% confidence)", subtitle_style))
            if f.ai_explanation:
                story.append(Spacer(1, 4))
                why_clean = f.ai_explanation.get("why_detected", "").replace("\n", "<br/>")
                story.append(Paragraph(f"<b>Why Detected:</b> {why_clean}", body_style))
            if f.remediation:
                story.append(Spacer(1, 4))
                story.append(Paragraph(f"<b>Remediation:</b> {f.remediation.get('recommendation', '')}", body_style))
            story.append(Spacer(1, 10))

        doc.build(story)
        return buffer.getvalue()
