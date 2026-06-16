"""
PDF Report Generation using ReportLab.
Generates professional security scan reports with charts and recommendations.
"""
import io
import logging
from datetime import datetime
from typing import Dict, Any

logger = logging.getLogger(__name__)


def generate_scan_report(scan_data: Dict[str, Any]) -> bytes:
    """
    Generate a professional PDF report for a scan.
    Returns PDF as bytes.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, KeepTogether
        )
        from reportlab.graphics.shapes import Drawing, Rect, String
        from reportlab.graphics.charts.barcharts import VerticalBarChart
        from reportlab.graphics import renderPDF

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm,
        )

        styles = getSampleStyleSheet()
        story = []

        # Color palette
        DARK = colors.HexColor("#0d1117")
        ACCENT = colors.HexColor("#00d4aa")
        DANGER = colors.HexColor("#ff4757")
        WARNING = colors.HexColor("#ffa502")
        INFO = colors.HexColor("#1e90ff")
        LIGHT_BG = colors.HexColor("#f8f9fa")

        SEVERITY_COLORS = {
            "critical": DANGER,
            "high": colors.HexColor("#ff6b35"),
            "medium": WARNING,
            "low": colors.HexColor("#2ed573"),
        }

        # Custom styles
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Title"],
            fontSize=24,
            textColor=DARK,
            spaceAfter=6,
            fontName="Helvetica-Bold",
        )
        heading_style = ParagraphStyle(
            "Heading",
            parent=styles["Heading1"],
            fontSize=14,
            textColor=ACCENT,
            fontName="Helvetica-Bold",
            spaceBefore=16,
            spaceAfter=8,
        )
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=10,
            textColor=DARK,
            spaceAfter=4,
        )

        # ── Header ──────────────────────────────────────────────────
        story.append(Paragraph("🔍 NetScan AI", title_style))
        story.append(Paragraph("Network Security Scan Report", styles["Heading2"]))
        story.append(HRFlowable(width="100%", thickness=2, color=ACCENT))
        story.append(Spacer(1, 0.5*cm))

        # ── Scan Metadata ────────────────────────────────────────────
        meta = [
            ["Scan Name", scan_data.get("name", "N/A")],
            ["Target", scan_data.get("target", "N/A")],
            ["Scan Date", scan_data.get("created_at", datetime.now().isoformat())[:19]],
            ["Duration", f"{scan_data.get('duration_seconds', 0):.1f}s"],
            ["Status", scan_data.get("status", "completed").upper()],
        ]
        meta_table = Table(meta, colWidths=[4*cm, 12*cm])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), LIGHT_BG),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.5*cm))

        # ── Executive Summary ────────────────────────────────────────
        story.append(Paragraph("Executive Summary", heading_style))

        risk_level = scan_data.get("risk_level", "low").upper()
        risk_color = SEVERITY_COLORS.get(scan_data.get("risk_level", "low"), INFO)

        summary_data = [
            ["Metric", "Value"],
            ["Total Hosts Scanned", str(scan_data.get("total_hosts", 0))],
            ["Hosts Online", str(scan_data.get("hosts_up", 0))],
            ["Total Open Ports", str(scan_data.get("total_open_ports", 0))],
            ["High Risk Hosts", str(scan_data.get("high_risk_hosts", 0))],
            ["Overall Risk Score", f"{scan_data.get('risk_score', 0):.1f}/100"],
            ["Risk Level", risk_level],
        ]

        summary_table = Table(summary_data, colWidths=[8*cm, 8*cm])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 1), (-1, -1), LIGHT_BG),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(summary_table)

        # ── Port Distribution ────────────────────────────────────────
        port_dist = scan_data.get("port_distribution", {})
        if port_dist:
            story.append(Paragraph("Top Open Ports Distribution", heading_style))

            top_ports = sorted(port_dist.items(), key=lambda x: x[1], reverse=True)[:10]
            port_table_data = [["Port", "Service", "Count", "Risk Level"]]

            from app.services.scanner import KNOWN_SERVICES, PORT_RISK_WEIGHTS
            for port_str, count in top_ports:
                port_num = int(port_str)
                service = KNOWN_SERVICES.get(port_num, "Unknown")
                risk_w = PORT_RISK_WEIGHTS.get(port_num, 0.2)
                if risk_w >= 0.7:
                    risk = "HIGH"
                elif risk_w >= 0.4:
                    risk = "MEDIUM"
                else:
                    risk = "LOW"
                port_table_data.append([str(port_num), service, str(count), risk])

            port_table = Table(port_table_data, colWidths=[3*cm, 6*cm, 3*cm, 4*cm])
            port_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(port_table)

        # ── AI Recommendations ───────────────────────────────────────
        recommendations = scan_data.get("ai_recommendations", [])
        if recommendations:
            story.append(Paragraph("AI Security Recommendations", heading_style))

            for i, rec in enumerate(recommendations[:10], 1):
                severity = rec.get("severity", "low")
                sev_color = SEVERITY_COLORS.get(severity, INFO)

                rec_data = [
                    [f"[{i}] {rec.get('title', 'N/A')}", f"Severity: {severity.upper()}"],
                    [rec.get("description", ""), ""],
                    [f"Action: {rec.get('recommendation', '')}", ""],
                ]

                if rec.get("cve_refs"):
                    rec_data.append([f"CVE References: {', '.join(rec['cve_refs'])}", ""])

                rec_table = Table(rec_data, colWidths=[13*cm, 3*cm])
                rec_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), sev_color),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (0, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#fff8f8")),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("SPAN", (0, 1), (-1, 1)),
                    ("SPAN", (0, 2), (-1, 2)),
                ]))
                story.append(KeepTogether([rec_table, Spacer(1, 0.3*cm)]))

        # ── Footer ───────────────────────────────────────────────────
        story.append(Spacer(1, 1*cm))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        story.append(Paragraph(
            f"Generated by NetScan AI | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Confidential",
            ParagraphStyle("Footer", parent=styles["Normal"], fontSize=8, textColor=colors.grey)
        ))

        doc.build(story)
        return buffer.getvalue()

    except ImportError:
        logger.error("ReportLab not installed. Cannot generate PDF.")
        raise RuntimeError("PDF generation requires: pip install reportlab")
