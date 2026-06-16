"""
Email Alert Service
Sends automatic alerts when high/critical risk scans are detected.
"""
import aiosmtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List
from app.core.config import settings

logger = logging.getLogger(__name__)


async def send_email(to_emails: List[str], subject: str, html_body: str):
    """Send an HTML email via SMTP."""
    try:
        message = MIMEMultipart("alternative")
        message["From"] = settings.SMTP_USER
        message["To"] = ", ".join(to_emails)
        message["Subject"] = subject
        message.attach(MIMEText(html_body, "html"))

        await aiosmtplib.send(
            message,
            hostname=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            username=settings.SMTP_USER,
            password=settings.SMTP_PASSWORD,
            use_tls=True,
        )
        logger.info(f"Alert email sent to {to_emails}")
        return True
    except Exception as e:
        logger.error(f"Email send failed: {e}")
        return False


async def send_risk_alert(
    scan_name: str,
    target: str,
    risk_level: str,
    risk_score: float,
    high_risk_hosts: int,
    recommendations: list,
    to_emails: List[str],
):
    """Send a professional risk alert email."""

    severity_color = {
        "critical": "#ff4757",
        "high": "#ff6b35",
        "medium": "#ffa502",
        "low": "#2ed573",
    }.get(risk_level, "#8b949e")

    rec_html = ""
    for rec in recommendations[:3]:
        rec_html += f"""
        <tr>
            <td style="padding:8px 12px; border-bottom:1px solid #eee;">
                <span style="color:{severity_color}; font-weight:bold; font-size:12px;">
                    [{rec.get('severity','').upper()}]
                </span>
                &nbsp;<strong>{rec.get('title', '')}</strong>
            </td>
        </tr>
        <tr>
            <td style="padding:4px 12px 12px; color:#666; font-size:13px; border-bottom:1px solid #eee;">
                ➤ {rec.get('recommendation', '')}
            </td>
        </tr>
        """

    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"></head>
    <body style="font-family:Arial,sans-serif; background:#f0f2f5; padding:30px; margin:0;">
        <div style="max-width:600px; margin:0 auto; background:white;
                    border-radius:16px; overflow:hidden;
                    box-shadow:0 4px 20px rgba(0,0,0,0.12);">

            <!-- Header -->
            <div style="background:#0d1117; padding:28px; text-align:center;">
                <h1 style="color:#00d4aa; margin:0; font-size:26px; letter-spacing:-1px;">
                    🔍 NetScan AI
                </h1>
                <p style="color:#8b949e; margin:6px 0 0; font-size:14px;">
                    Automated Security Alert System
                </p>
            </div>

            <!-- Risk Banner -->
            <div style="background:{severity_color}; padding:18px; text-align:center;">
                <h2 style="color:white; margin:0; font-size:22px;">
                    ⚠️ {risk_level.upper()} RISK DETECTED
                </h2>
                <p style="color:rgba(255,255,255,0.85); margin:6px 0 0; font-size:14px;">
                    Immediate attention required
                </p>
            </div>

            <!-- Scan Details -->
            <div style="padding:28px;">
                <h3 style="color:#0d1117; margin:0 0 16px;
                           border-bottom:2px solid #00d4aa; padding-bottom:8px;">
                    📋 Scan Details
                </h3>
                <table style="width:100%; border-collapse:collapse;
                              border:1px solid #eee; border-radius:8px;
                              overflow:hidden; margin-bottom:24px;">
                    <tr style="background:#f8f9fa;">
                        <td style="padding:12px 16px; font-weight:bold;
                                   color:#555; width:40%; border-bottom:1px solid #eee;">
                            Scan Name
                        </td>
                        <td style="padding:12px 16px; border-bottom:1px solid #eee;">
                            {scan_name}
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:12px 16px; font-weight:bold;
                                   color:#555; background:#f8f9fa; border-bottom:1px solid #eee;">
                            Target
                        </td>
                        <td style="padding:12px 16px; font-family:monospace;
                                   border-bottom:1px solid #eee;">
                            {target}
                        </td>
                    </tr>
                    <tr style="background:#f8f9fa;">
                        <td style="padding:12px 16px; font-weight:bold;
                                   color:#555; border-bottom:1px solid #eee;">
                            Risk Score
                        </td>
                        <td style="padding:12px 16px; color:{severity_color};
                                   font-weight:bold; font-size:22px;
                                   border-bottom:1px solid #eee;">
                            {risk_score:.1f} <span style="font-size:14px;color:#999;">/ 100</span>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:12px 16px; font-weight:bold; color:#555;">
                            High Risk Hosts
                        </td>
                        <td style="padding:12px 16px; color:{severity_color};
                                   font-weight:bold; font-size:18px;">
                            {high_risk_hosts} hosts
                        </td>
                    </tr>
                </table>

                <!-- Recommendations -->
                <h3 style="color:#0d1117; margin:0 0 16px;
                           border-bottom:2px solid #00d4aa; padding-bottom:8px;">
                    🤖 Top AI Security Recommendations
                </h3>
                <table style="width:100%; border-collapse:collapse;
                              border:1px solid #eee; border-radius:8px;
                              overflow:hidden; margin-bottom:28px;">
                    {rec_html if rec_html else
                     '<tr><td style="padding:12px;">No critical recommendations.</td></tr>'}
                </table>

                <!-- CTA Button -->
                <div style="text-align:center; margin-top:8px;">
                    <a href="http://localhost:3000/scans"
                       style="background:#00d4aa; color:#000; padding:14px 32px;
                              text-decoration:none; border-radius:8px;
                              font-weight:bold; font-size:15px;
                              display:inline-block;">
                        🔍 View Full Scan Report
                    </a>
                </div>
            </div>

            <!-- Footer -->
            <div style="background:#f8f9fa; padding:18px;
                        text-align:center; border-top:1px solid #eee;">
                <p style="color:#8b949e; font-size:12px; margin:0;">
                    NetScan AI — Automated Security Alert System<br>
                    This is an automated message. Please do not reply to this email.
                </p>
            </div>
        </div>
    </body>
    </html>
    """

    subject = f"[NetScan AI] ⚠️ {risk_level.upper()} Risk Alert — {scan_name}"
    return await send_email(to_emails, subject, html_body)