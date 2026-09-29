"""
PDF Report Generator
=====================
Generates professional security reports from alert data.
"""

from fpdf import FPDF
from datetime import datetime
from typing import List, Dict, Any
import os
import re


def clean_text(text: Any) -> str:
    """Sanitize text to be safely encodable in standard PDF Latin-1 fonts."""
    if text is None:
        return "-"
    s = str(text)
    # Common Unicode replacements
    replacements = {
        "—": "-",
        "–": "-",
        "“": '"',
        "”": '"',
        "‘": "'",
        "’": "'",
        "•": "*",
        "…": "...",
        "→": "->",
        "←": "<-",
        "◈": "*",
        "🚨": "[!]",
        "⚠️": "[!]",
        "🔴": "[HIGH]",
        "🟡": "[MED]",
        "🟢": "[LOW]",
        "✅": "[OK]",
        "❌": "[X]",
    }
    for orig, rep in replacements.items():
        s = s.replace(orig, rep)
    # Filter non-latin1 characters
    s = s.encode("latin-1", "replace").decode("latin-1")
    return s


class SecurityReport(FPDF):
    """Professional security report PDF generator."""

    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        self.set_font("Helvetica", "B", 18)
        self.set_text_color(30, 30, 40)
        self.cell(0, 10, clean_text("SOC-NIDS // THREAT COMMAND"), align="C", ln=1)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(100, 100, 120)
        self.cell(0, 6, clean_text("Security Operations Center - Network Intrusion Detection Report"), align="C", ln=1)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(150, 150, 160)
        self.cell(0, 10, clean_text(f"Page {self.page_no()}/{{nb}} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} | Classification: CONFIDENTIAL"), align="C")

    def section_title(self, title: str):
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(40, 40, 60)
        self.cell(0, 10, clean_text(title), ln=1)
        self.set_draw_color(0, 180, 100)
        self.line(10, self.get_y(), 60, self.get_y())
        self.ln(4)

    def metric_row(self, metrics: List[tuple]):
        """metrics: list of (label, value) tuples"""
        self.set_font("Helvetica", "B", 22)
        self.set_text_color(0, 180, 100)
        col_w = 190 / max(len(metrics), 1)
        for label, value in metrics:
            self.cell(col_w, 10, clean_text(str(value)), align="C")
        self.ln()
        self.set_font("Helvetica", "", 8)
        self.set_text_color(120, 120, 140)
        for label, value in metrics:
            self.cell(col_w, 6, clean_text(label.upper()), align="C")
        self.ln(8)

    def alert_table(self, alerts: List[Dict], max_rows: int = 25):
        """Render alerts as a table."""
        if not alerts:
            self.set_font("Helvetica", "I", 9)
            self.set_text_color(100, 100, 120)
            self.cell(0, 8, clean_text("No threat incidents recorded during this monitoring interval."), align="C", ln=1)
            return

        self.set_font("Helvetica", "B", 8)
        self.set_fill_color(240, 240, 245)
        headers = ["Time", "Type", "Severity", "Score", "Source", "Summary"]
        widths = [25, 25, 18, 18, 35, 69]

        for h, w in zip(headers, widths):
            self.cell(w, 7, clean_text(h), border=1, fill=True, align="C")
        self.ln()

        self.set_font("Helvetica", "", 7)
        for i, alert in enumerate(alerts[:max_rows]):
            if i % 2 == 0:
                self.set_fill_color(250, 250, 252)
            else:
                self.set_fill_color(255, 255, 255)

            sev = str(alert.get("severity", "low")).lower()
            if sev in ["high", "critical"]:
                self.set_text_color(220, 50, 50)
            elif sev == "medium":
                self.set_text_color(220, 150, 30)
            else:
                self.set_text_color(30, 180, 80)

            ts = alert.get("timestamp", "")
            time_str = ts[-8:] if len(ts) >= 8 else "--:--"

            row = [
                time_str,
                clean_text(alert.get("attack_type") or "Benign")[:15],
                sev.upper(),
                f"{float(alert.get('final_score', 0)):.1%}",
                clean_text(alert.get("source_ip") or "-")[:15],
                clean_text(alert.get("packet_summary") or "-")[:40],
            ]
            for v, w in zip(row, widths):
                self.cell(w, 6, clean_text(v), border=1, fill=True, align="C")
            self.ln()
        self.set_text_color(30, 30, 40)


def generate_report(alerts: List[Dict], output_path: str = None) -> str:
    """
    Generate a PDF security report.

    Args:
        alerts: List of alert dictionaries
        output_path: Path to save PDF (default: reports/)

    Returns:
        Path to generated PDF
    """
    if output_path is None:
        os.makedirs("reports", exist_ok=True)
        output_path = f"reports/soc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    else:
        out_dir = os.path.dirname(output_path)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

    if alerts is None:
        alerts = []

    pdf = SecurityReport()
    pdf.alias_nb_pages()
    pdf.add_page()

    # Summary metrics
    total = len(alerts)
    high = sum(1 for a in alerts if str(a.get("severity", "")).lower() in ["high", "critical"])
    medium = sum(1 for a in alerts if str(a.get("severity", "")).lower() == "medium")
    low = sum(1 for a in alerts if str(a.get("severity", "")).lower() == "low")
    attack_types = {}
    for a in alerts:
        at = a.get("attack_type", "Unknown")
        attack_types[at] = attack_types.get(at, 0) + 1

    pdf.section_title("EXECUTIVE SUMMARY")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 80)
    summary_text = (
        f"This report contains analysis of {total} security alerts detected by the SOC-NIDS Threat Command system. "
        f"{high} critical/high severity incidents were identified requiring immediate attention."
        if total > 0 else
        "This report summarizes the operational status of the SOC-NIDS Threat Command system. "
        "No security intrusions or malicious alerts were detected during this monitoring cycle."
    )
    pdf.multi_cell(0, 5, clean_text(summary_text))
    pdf.ln(4)

    pdf.section_title("KEY METRICS")
    pdf.metric_row([
        ("Total Alerts", total),
        ("Critical/High", high),
        ("Medium", medium),
        ("Low", low),
    ])

    if attack_types:
        pdf.section_title("ATTACK DISTRIBUTION")
        pdf.set_font("Helvetica", "", 9)
        for at, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
            pdf.cell(60, 6, clean_text(f"  {at}"))
            pdf.cell(30, 6, clean_text(str(count)), align="R")
            bar_w = min(count * 3, 90)
            pdf.set_fill_color(0, 180, 100)
            pdf.cell(bar_w, 4, "", fill=True)
            pdf.ln()
        pdf.ln(6)

    pdf.section_title("ALERT DETAILS")
    pdf.alert_table(alerts)

    pdf.ln(8)
    pdf.section_title("CONCLUSIONS & RECOMMENDATIONS")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 80)
    pdf.multi_cell(0, 5, clean_text(
        "The SOC-NIDS system continuously inspects network flow telemetry using hybrid ML and signature detection. "
        "Continued monitoring, signature updates, and periodic validation of detection thresholds are recommended to maintain optimal network defense."
    ))

    pdf.output(output_path)
    print(f"[ReportGenerator] PDF saved: {output_path}")
    return output_path


class ReportGenerator:
    """Helper wrapper for generating security reports."""
    @staticmethod
    def generate_pdf_report(alerts: List[Dict] = None, output_path: str = None, **kwargs) -> str:
        return generate_report(alerts or [], output_path=output_path)

