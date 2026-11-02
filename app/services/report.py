"""
SentinelFlow Incident & Intelligence Reporting Service
Generates professional PDF audit reports using ReportLab,
as well as CSV export streams for SIEM and security analysts.
"""

import io
import csv
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

def generate_pdf_report(stats: dict, recent_alerts: list) -> io.BytesIO:
    """
    Creates an executive NIDS threat intelligence report in PDF format.
    Styled with warm amber and orange brand accents.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom Brand Styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#F97316") # Brand Orange
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#8A7568")
    )
    heading2_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#3B2F2A"),
        spaceBefore=14,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#3B2F2A")
    )
    table_text_style = ParagraphStyle(
        "TableText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#3B2F2A")
    )
    table_header_style = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        textColor=colors.white
    )

    story = []

    # Title & Header
    story.append(Paragraph("🛡️ SentinelFlow NIDS — Executive Security Report", title_style))
    story.append(Paragraph(f"Generated on {datetime.utcnow().strftime('%B %d, %Y at %H:%M:%S UTC')} | Environment: Active Sensor", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#F97316"), spaceBefore=8, spaceAfter=14))

    # Executive Summary Paragraph
    total_analyzed = stats.get("total_analyzed", 0)
    total_attacks = stats.get("total_attacks", 0)
    det_rate = stats.get("detection_rate", "0.0%")
    blocked_count = stats.get("blocked_ips", 0)

    summary_text = (
        f"This report presents an operational summary of network telemetry processed by the "
        f"SentinelFlow Network Intrusion Detection System. Over the analyzed period, <b>{total_analyzed:,}</b> "
        f"total connection records were evaluated. A total of <b>{total_attacks:,}</b> attack events "
        f"were identified ({det_rate} threat frequency), resulting in <b>{blocked_count}</b> dynamic IP mitigations. "
        f"Real-time explainability via SHAP attributions was applied to isolate malicious traffic signatures."
    )
    story.append(Paragraph("1. Executive Summary", heading2_style))
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 10))

    # KPI Metric Table
    kpi_data = [
        [
            Paragraph("<b>Total Evaluated</b>", table_header_style),
            Paragraph("<b>Attacks Detected</b>", table_header_style),
            Paragraph("<b>Threat Frequency</b>", table_header_style),
            Paragraph("<b>Mitigated IPs</b>", table_header_style)
        ],
        [
            Paragraph(f"{total_analyzed:,}", table_text_style),
            Paragraph(f"{total_attacks:,}", table_text_style),
            Paragraph(f"{det_rate}", table_text_style),
            Paragraph(f"{blocked_count}", table_text_style)
        ]
    ]
    t_kpi = Table(kpi_data, colWidths=[130, 130, 130, 130])
    t_kpi.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F97316")),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#FFF8F0")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#FED7AA")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#F97316")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6)
    ]))
    story.append(t_kpi)
    story.append(Spacer(1, 14))

    # Threat Breakdown by Category Table
    story.append(Paragraph("2. Threat Distribution by Category", heading2_style))
    breakdown_data = [
        [
            Paragraph("<b>Category</b>", table_header_style),
            Paragraph("<b>Count</b>", table_header_style),
            Paragraph("<b>Severity Baseline</b>", table_header_style),
            Paragraph("<b>Recommended Posture</b>", table_header_style)
        ]
    ]

    breakdown_counts = stats.get("attack_breakdown", {})
    for cat in ["DoS", "Probe", "R2L", "U2R", "Normal"]:
        cnt = breakdown_counts.get(cat, 0)
        sev = "Critical" if cat == "U2R" else ("High" if cat in ("DoS", "R2L") else ("Medium" if cat == "Probe" else "Low"))
        rec = (
            "Immediate host isolation & memory triage" if cat == "U2R" else
            ("Rate limiting & edge packet drop" if cat == "DoS" else
            ("Port filter & ACL inspection" if cat == "Probe" else
            ("Credential revocation & 2FA enforcement" if cat == "R2L" else "Baseline monitored")))
        )
        breakdown_data.append([
            Paragraph(f"<b>{cat}</b>", table_text_style),
            Paragraph(f"{cnt:,}", table_text_style),
            Paragraph(sev, table_text_style),
            Paragraph(rec, table_text_style)
        ])

    t_breakdown = Table(breakdown_data, colWidths=[80, 70, 110, 260])
    t_breakdown.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3B2F2A")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FFF8F0")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5D5C5")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#8A7568")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5)
    ]))
    story.append(t_breakdown)
    story.append(Spacer(1, 14))

    # Recent Alerts Log
    story.append(Paragraph("3. Recent High-Severity Security Incidents", heading2_style))
    alerts_data = [
        [
            Paragraph("<b>ID</b>", table_header_style),
            Paragraph("<b>Attack Type</b>", table_header_style),
            Paragraph("<b>Severity</b>", table_header_style),
            Paragraph("<b>Risk</b>", table_header_style),
            Paragraph("<b>Source IP</b>", table_header_style),
            Paragraph("<b>Detection Explanation (SHAP)</b>", table_header_style)
        ]
    ]

    if recent_alerts:
        for al in recent_alerts[:8]:
            alerts_data.append([
                Paragraph(str(al.get("id", "")), table_text_style),
                Paragraph(f"<b>{al.get('attack_type', '')}</b>", table_text_style),
                Paragraph(al.get("severity", ""), table_text_style),
                Paragraph(f"{al.get('risk_score', 0):.1f}", table_text_style),
                Paragraph(al.get("source_ip", ""), table_text_style),
                Paragraph(al.get("explanation", "Standard model signature match")[:120] + "...", table_text_style)
            ])
    else:
        alerts_data.append([
            Paragraph("-", table_text_style),
            Paragraph("No active alerts logged", table_text_style),
            Paragraph("-", table_text_style),
            Paragraph("-", table_text_style),
            Paragraph("-", table_text_style),
            Paragraph("System state clear", table_text_style)
        ])

    t_alerts = Table(alerts_data, colWidths=[30, 75, 55, 45, 95, 220])
    t_alerts.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DC2626")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FFEFD9")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#FED7AA")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#DC2626")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5)
    ]))
    story.append(t_alerts)
    story.append(Spacer(1, 14))

    # Recommendations
    story.append(Paragraph("4. Recommended Defensive Actions", heading2_style))
    recs = (
        "• <b>Edge Hardening</b>: Review top offending source IP blocks and verify perimeter firewall rules.<br/>"
        "• <b>Credential Hygiene</b>: Investigate hosts targeted with R2L/U2R vectors for potential password reuse.<br/>"
        "• <b>Model Monitoring</b>: Regularly check Model Lab drift indicators and retrain with newly recorded samples.<br/>"
        "• <b>Analyst Sign-off</b>: Triage any remaining 'New' status alerts to prevent unmonitored lateral movement."
    )
    story.append(Paragraph(recs, body_style))

    doc.build(story)
    buffer.seek(0)
    return buffer

def generate_csv_export(records: list, record_type: str = "predictions") -> str:
    """Generates standard CSV content as string."""
    output = io.StringIO()
    if not records:
        return ""

    if record_type == "alerts":
        fieldnames = ["id", "attack_type", "severity", "risk_score", "confidence", "source_ip", "status", "created_at", "explanation"]
    else:
        fieldnames = ["id", "attack_type", "confidence", "risk_score", "threat_level", "traffic_status", "source_ip", "protocol_type", "service", "flag", "timestamp", "analyst_status"]

    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for r in records:
        writer.writerow(r)

    return output.getvalue()
