from fastapi import APIRouter, HTTPException, Query, Response
from backend.api.storage import ScanStore
from backend.reports.sarif import SarifExporter
from backend.reports.html import HtmlReportExporter
from backend.reports.pdf import PdfReportExporter

router = APIRouter(prefix="/api/scans", tags=["Reports"])

@router.get("/{scan_id}/report")
async def get_scan_report(
    scan_id: str,
    format: str = Query("json", description="Report format: json, sarif, html, or pdf")
):
    """Generates and downloads security assessment report in JSON, SARIF, HTML, or PDF format."""
    scan = ScanStore.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

    fmt = format.lower().strip()

    if fmt == "sarif":
        sarif_content = SarifExporter.export_json_string(scan)
        return Response(
            content=sarif_content,
            media_type="application/sarif+json",
            headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.sarif"}
        )

    elif fmt == "html":
        html_content = HtmlReportExporter.render(scan)
        return Response(
            content=html_content,
            media_type="text/html",
            headers={"Content-Disposition": f"inline; filename=scan_{scan_id}.html"}
        )

    elif fmt == "pdf":
        try:
            pdf_bytes = PdfReportExporter.render_bytes(scan)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.pdf"}
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"PDF generation error: {e}")

    else:
        # Default JSON format
        return Response(
            content=scan.model_dump_json(indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.json"}
        )
