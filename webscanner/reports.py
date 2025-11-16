from pathlib import Path
from datetime import datetime
import csv

from django.template.loader import render_to_string
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors

from .models import Scan, Vulnerability, Target

# Folder for storing reports
REPORTS_DIR = Path('reports')
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def _scan_context(scan_id: int):
    """Return scan, target, and vulnerabilities"""
    scan = Scan.objects.get(id=scan_id)
    target = scan.target
    vulns = Vulnerability.objects.filter(scan=scan)
    return scan, target, vulns


# ================================
#  PDF REPORT
# ================================
def generate_pdf_report(scan_id: int) -> str:
    scan, target, vulns = _scan_context(scan_id)

    filename = REPORTS_DIR / f"report_{scan_id}.pdf"
    doc = SimpleDocTemplate(str(filename), pagesize=A4)

    styles = getSampleStyleSheet()
    elems = []

    elems.append(Paragraph("Project Sentinel (SPIDER) – Scan Report", styles["Title"]))
    elems.append(Spacer(1, 12))

    elems.append(Paragraph(f"Target: {target.name} ({target.url})", styles["Normal"]))
    elems.append(Paragraph(f"Scan ID: {scan.id} | Type: {scan.scan_type} | Status: {scan.status}", styles["Normal"]))
    elems.append(Paragraph(f"Started: {scan.started_at} | Finished: {scan.finished_at}", styles["Normal"]))
    elems.append(Spacer(1, 12))

    data = [["Type", "Severity", "URL", "Parameter", "Status"]]
    for v in vulns:
        data.append([
            v.vtype,
            v.severity,
            v.url or "",
            v.parameter or "",
            v.status
        ])

    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d1117")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey])
    ]))

    elems.append(table)
    doc.build(elems)

    return str(filename)


# ================================
#  HTML REPORT
# ================================
def generate_html_report(scan_id: int) -> str:
    scan, target, vulns = _scan_context(scan_id)

    filename = REPORTS_DIR / f"report_{scan_id}.html"

    # Django HTML using string building (same structure as Flask)
    rows = "".join([
        f"<tr><td>{v.vtype}</td><td>{v.severity}</td><td>{v.url or ''}</td>"
        f"<td>{v.parameter or ''}</td><td>{v.status}</td></tr>"
        for v in vulns
    ])

    html = f"""
<!doctype html>
<html>
<head>
<meta charset='utf-8'>
<title>SPIDER Report {scan.id}</title>
<style>
body {{
    font-family: Arial;
    background: #0d1117;
    color: #e5e7eb;
}}
table {{
    width: 100%;
    border-collapse: collapse;
}}
th, td {{
    border: 1px solid #334155;
    padding: 8px;
}}
</style>
</head>
<body>
<h1>Project Sentinel (SPIDER) - Scan Report</h1>
<p>Target: {target.name} ({target.url})</p>
<p>Scan ID: {scan.id} | Type: {scan.scan_type} | Status: {scan.status}</p>
<p>Started: {scan.started_at} | Finished: {scan.finished_at}</p>

<table>
<thead>
<tr><th>Type</th><th>Severity</th><th>URL</th><th>Parameter</th><th>Status</th></tr>
</thead>
<tbody>
{rows}
</tbody>
</table>

</body>
</html>
"""
    filename.write_text(html, encoding="utf-8")
    return str(filename)


# ================================
#  CSV REPORT
# ================================
def generate_csv_report(scan_id: int) -> str:
    _, _, vulns = _scan_context(scan_id)

    filename = REPORTS_DIR / f"report_{scan_id}.csv"

    with filename.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        writer.writerow(["Type", "Severity", "URL", "Parameter", "Status", "Evidence", "Remediation"])

        for v in vulns:
            writer.writerow([
                v.vtype,
                v.severity,
                v.url or "",
                v.parameter or "",
                v.status,
                (v.evidence or "").replace("\n", " "),
                (v.remediation or "").replace("\n", " ")
            ])

    return str(filename)
