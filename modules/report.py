from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
import os
import json
from datetime import datetime

TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "..", "templates")

def severity_color(sev):
    return {
        "critical": "#c0392b",
        "high": "#e67e22",
        "medium": "#f1c40f",
        "low": "#27ae60"
    }.get(sev.lower(), "#95a5a6")

def generate_report(results, output_dir):
    env = Environment(loader=FileSystemLoader(TEMPLATE_PATH))
    env.filters["severity_color"] = severity_color
    tmpl = env.get_template("report_template.html")

    meta = results.get("meta", {})
    ports = results.get("portscan", {}).get("open_ports", [])
    vulns = results.get("vulnscan", {}).get("nse_vulns", [])
    severity = results.get("vulnscan", {}).get("severity_summary", {})
    exploits = results.get("exploit", {}).get("attempted", [])

    http_findings = []
    for h in results.get("enum", {}).get("http", []):
        http_findings.extend(h.get("findings", []))

    risk = (
        severity.get("critical", 0) * 10 +
        severity.get("high", 0) * 7 +
        severity.get("medium", 0) * 4 +
        severity.get("low", 0)
    )
    risk_label = (
        "Critical" if risk >= 20 else
        "High" if risk >= 10 else
        "Medium" if risk >= 5 else
        "Low"
    )

    html = tmpl.render(
        target=meta.get("target", "N/A"),
        tester=meta.get("tester", "Anveeksh M Rao"),
        engagement=meta.get("engagement", "Lab Assessment"),
        timestamp=meta.get("timestamp", datetime.now().isoformat()),
        ports=ports,
        vulns=vulns,
        severity=severity,
        exploits=exploits,
        http_findings=http_findings,
        risk_score=risk,
        risk_label=risk_label,
        total_ports=len(ports),
        total_vulns=len(vulns),
    )

    pdf_path = os.path.join(output_dir, "pentest_report.pdf")
    HTML(string=html, base_url=TEMPLATE_PATH).write_pdf(pdf_path)
    return pdf_path
