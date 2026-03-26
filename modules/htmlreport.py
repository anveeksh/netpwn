import os
import json
from datetime import datetime

def severity_color(sev):
    return {
        "critical": "#c0392b",
        "high":     "#e67e22",
        "medium":   "#f39c12",
        "low":      "#27ae60",
        "unknown":  "#95a5a6"
    }.get(str(sev).lower(), "#95a5a6")

def risk_label(severity_summary):
    c = severity_summary.get("critical", 0)
    h = severity_summary.get("high", 0)
    m = severity_summary.get("medium", 0)
    score = c * 10 + h * 7 + m * 4
    if score >= 20: return "Critical", "#c0392b"
    if score >= 10: return "High",     "#e67e22"
    if score >= 5:  return "Medium",   "#f39c12"
    return "Low", "#27ae60"

def generate_html_report(results, output_dir):
    meta      = results.get("meta", {})
    ports     = results.get("portscan", {}).get("open_ports", [])
    vulns     = results.get("vulnscan", {}).get("nse_vulns", [])
    severity  = results.get("vulnscan", {}).get("severity_summary", {})
    exploits  = results.get("exploit",  {}).get("attempted", [])
    recon     = results.get("recon",    {})
    http_findings = []
    for h in results.get("enum", {}).get("http", []):
        http_findings.extend(h.get("findings", []))

    rlabel, rcolor = risk_label(severity)
    timestamp = meta.get("timestamp", datetime.now().isoformat())

    # Build vuln rows
    vuln_rows = ""
    for v in vulns:
        sc = v.get("cvss_score", "N/A")
        sev = v.get("severity", "unknown")
        col = severity_color(sev)
        vuln_rows += f"""
        <tr>
          <td>{v.get('name','N/A')}</td>
          <td><a href="https://nvd.nist.gov/vuln/detail/{v.get('cve','')}" target="_blank">{v.get('cve','N/A')}</a></td>
          <td><span style="background:{col};color:white;padding:2px 10px;border-radius:10px;font-size:11px">{sev.capitalize()}</span></td>
          <td><strong>{sc}</strong></td>
          <td style="font-size:11px;color:#666">{v.get('cvss_vector','N/A')}</td>
        </tr>"""

    # Build port rows
    port_rows = ""
    for p in ports:
        port_rows += f"""
        <tr>
          <td><strong>{p.get('port')}</strong></td>
          <td>{p.get('protocol')}</td>
          <td>{p.get('service')}</td>
          <td>{p.get('product','')} {p.get('version','')}</td>
        </tr>"""

    # Build exploit rows
    exploit_rows = ""
    for e in exploits:
        exploit_rows += f"""
        <tr>
          <td>{e.get('service')}</td>
          <td>{e.get('exploit')}</td>
          <td><span style="background:#e67e22;color:white;padding:2px 8px;border-radius:8px;font-size:11px">Available</span></td>
        </tr>"""

    # HTTP findings
    http_html = ""
    for f in http_findings:
        http_html += f'<div class="finding">{f}</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pentest Report — {meta.get('target','N/A')}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f0f2f5; color: #2c3e50; }}
  .header {{ background: linear-gradient(135deg, #1a252f, #2980b9); color: white; padding: 40px; }}
  .header h1 {{ font-size: 28px; margin-bottom: 6px; }}
  .header p {{ opacity: 0.8; font-size: 14px; }}
  .badge {{ display:inline-block; padding:6px 18px; border-radius:20px; color:white;
            font-weight:bold; background:{rcolor}; font-size:14px; margin-top:12px; }}
  .container {{ max-width: 1100px; margin: 30px auto; padding: 0 20px; }}
  .card {{ background: white; border-radius: 10px; padding: 28px; margin-bottom: 24px;
           box-shadow: 0 2px 8px rgba(0,0,0,0.07); }}
  .card h2 {{ font-size: 18px; color: #2980b9; border-left: 4px solid #2980b9;
              padding-left: 12px; margin-bottom: 18px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(4,1fr); gap: 14px; margin-bottom: 24px; }}
  .summary-card {{ border-radius: 10px; padding: 20px; text-align: center; color: white; }}
  .summary-card .num {{ font-size: 36px; font-weight: bold; }}
  .summary-card .lbl {{ font-size: 12px; text-transform: uppercase; letter-spacing: 1px; opacity:.85; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th {{ background:#2980b9; color:white; padding:10px 12px; text-align:left; }}
  td {{ padding:9px 12px; border-bottom:1px solid #eee; }}
  tr:hover {{ background:#f8f9fa; }}
  .meta-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:12px; }}
  .meta-item {{ background:#f8f9fa; border-radius:8px; padding:12px 16px; }}
  .meta-item .label {{ font-size:11px; color:#999; text-transform:uppercase; letter-spacing:1px; }}
  .meta-item .value {{ font-size:14px; font-weight:600; margin-top:4px; }}
  .finding {{ background:#fef9e7; border-left:3px solid #f39c12; padding:8px 12px;
              margin:5px 0; font-size:12px; border-radius:0 6px 6px 0; }}
  .rec-table td:first-child {{ font-weight:600; width:120px; }}
  .disclaimer {{ background:#fdf2f2; border:1px solid #e74c3c; border-radius:8px;
                 padding:14px; font-size:12px; color:#7b241c; margin-top:8px; }}
  .footer {{ text-align:center; padding:30px; font-size:12px; color:#999; }}
  a {{ color:#2980b9; }}
</style>
</head>
<body>

<div class="header">
  <h1>🔒 Network Penetration Test Report</h1>
  <p>Confidential — Authorized Assessment Only</p>
  <div class="badge">Overall Risk: {rlabel}</div>
</div>

<div class="container">

  <!-- Meta -->
  <div class="card">
    <h2>Engagement Details</h2>
    <div class="meta-grid">
      <div class="meta-item"><div class="label">Target</div><div class="value">{meta.get('target','N/A')}</div></div>
      <div class="meta-item"><div class="label">Tester</div><div class="value">{meta.get('tester','N/A')}</div></div>
      <div class="meta-item"><div class="label">Engagement</div><div class="value">{meta.get('engagement','N/A')}</div></div>
      <div class="meta-item"><div class="label">Date</div><div class="value">{timestamp[:10]}</div></div>
      <div class="meta-item"><div class="label">Alive Hosts</div><div class="value">{len(recon.get('alive_hosts',[]))}</div></div>
      <div class="meta-item"><div class="label">Open Ports</div><div class="value">{len(ports)}</div></div>
    </div>
  </div>

  <!-- Severity Summary -->
  <div class="summary-grid">
    <div class="summary-card" style="background:#c0392b"><div class="num">{severity.get('critical',0)}</div><div class="lbl">Critical</div></div>
    <div class="summary-card" style="background:#e67e22"><div class="num">{severity.get('high',0)}</div><div class="lbl">High</div></div>
    <div class="summary-card" style="background:#f39c12"><div class="num">{severity.get('medium',0)}</div><div class="lbl">Medium</div></div>
    <div class="summary-card" style="background:#27ae60"><div class="num">{severity.get('low',0)}</div><div class="lbl">Low</div></div>
  </div>

  <!-- Ports -->
  <div class="card">
    <h2>Open Ports & Services</h2>
    {"<table><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th></tr>" + port_rows + "</table>" if ports else "<p style='color:#999'>No open ports detected.</p>"}
  </div>

  <!-- Vulnerabilities -->
  <div class="card">
    <h2>Vulnerabilities (CVSS Scored)</h2>
    {"<table><tr><th>Name</th><th>CVE</th><th>Severity</th><th>CVSS Score</th><th>Vector</th></tr>" + vuln_rows + "</table>" if vulns else "<p style='color:#999'>No vulnerabilities detected.</p>"}
  </div>

  <!-- HTTP Findings -->
  {"'<div class=card><h2>Web Findings (Nikto)</h2>' + http_html + '</div>'" if http_findings else ""}

  <!-- Exploits -->
  {"'<div class=card><h2>Exploit Availability</h2><table><tr><th>Service</th><th>Exploit</th><th>Status</th></tr>' + exploit_rows + '</table></div>'" if exploits else ""}

  <!-- Recommendations -->
  <div class="card">
    <h2>Recommendations</h2>
    <table class="rec-table">
      <tr><td>🔴 Immediate</td><td>Patch Critical/High findings. Disable unused services and close unnecessary ports.</td></tr>
      <tr><td>🟠 Short-term</td><td>Enforce firewall rules. Harden exposed services. Review access controls.</td></tr>
      <tr><td>🟡 Medium-term</td><td>Deploy IDS/IPS. Implement centralized logging and alerting.</td></tr>
      <tr><td>🟢 Ongoing</td><td>Establish patch management. Schedule quarterly penetration tests.</td></tr>
    </table>
    <div class="disclaimer" style="margin-top:16px">
      ⚠️ This assessment was performed in an isolated lab environment on authorized systems only.
      Unauthorized use of these techniques is illegal under CFAA and equivalent laws.
    </div>
  </div>

</div>

<div class="footer">
  Generated by NetPwn Framework v1.0 &mdash; Anveeksh M Rao &mdash;
  <a href="https://anveekshmrao.com">anveekshmrao.com</a> |
  <a href="https://github.com/anveeksh">github.com/anveeksh</a>
</div>

</body>
</html>"""

    os.makedirs(output_dir, exist_ok=True)
    html_path = os.path.join(output_dir, "pentest_report.html")
    with open(html_path, "w") as f:
        f.write(html)
    print(f"  [report] HTML report saved → {html_path}")
    return html_path
