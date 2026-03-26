import requests
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ── Config — fill these in or load from config.yaml ──────
SLACK_WEBHOOK_URL = ""   # e.g. https://hooks.slack.com/services/XXX/YYY/ZZZ
EMAIL_SENDER      = ""   # e.g. yourname@gmail.com
EMAIL_PASSWORD    = ""   # Gmail app password
EMAIL_RECIPIENT   = ""   # e.g. client@company.com
SMTP_SERVER       = "smtp.gmail.com"
SMTP_PORT         = 587


# ── Slack ─────────────────────────────────────────────────

def send_slack_alert(results):
    """Send a Slack notification summarizing scan findings."""
    if not SLACK_WEBHOOK_URL:
        print("  [alerts] Slack webhook not configured, skipping.")
        return

    meta     = results.get("meta", {})
    ports    = results.get("portscan", {}).get("open_ports", [])
    vulns    = results.get("vulnscan", {}).get("nse_vulns", [])
    severity = results.get("vulnscan", {}).get("severity_summary", {})
    target   = meta.get("target", "N/A")

    crit = severity.get("critical", 0)
    high = severity.get("high", 0)

    # Only alert on critical or high findings
    if crit == 0 and high == 0:
        print(f"  [alerts] No critical/high findings for {target}, skipping Slack alert.")
        return

    color = "#da3633" if crit > 0 else "#d29922"

    vuln_list = "\n".join([
        f"• {v.get('cve','N/A')} — {v.get('severity','').upper()} (CVSS: {v.get('cvss_score','N/A')})"
        for v in vulns[:5]
    ])

    payload = {
        "attachments": [{
            "color": color,
            "title": f"🚨 NetPwn Alert — {target}",
            "text": (
                f"*Target:* `{target}`\n"
                f"*Open Ports:* {len(ports)}\n"
                f"*Findings:* Critical: {crit} | High: {high} | "
                f"Medium: {severity.get('medium',0)} | Low: {severity.get('low',0)}\n\n"
                f"*Top Vulnerabilities:*\n{vuln_list or 'None identified'}"
            ),
            "footer": "NetPwn Framework | github.com/anveeksh",
            "ts": __import__('time').time()
        }]
    }

    try:
        r = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
        if r.status_code == 200:
            print(f"  [alerts] Slack alert sent for {target}")
        else:
            print(f"  [alerts] Slack error: {r.status_code}")
    except Exception as e:
        print(f"  [alerts] Slack failed: {e}")


# ── Email ─────────────────────────────────────────────────

def send_email_alert(results):
    """Send an HTML email report to the configured recipient."""
    if not EMAIL_SENDER or not EMAIL_RECIPIENT:
        print("  [alerts] Email not configured, skipping.")
        return

    meta     = results.get("meta", {})
    ports    = results.get("portscan", {}).get("open_ports", [])
    vulns    = results.get("vulnscan", {}).get("nse_vulns", [])
    severity = results.get("vulnscan", {}).get("severity_summary", {})
    target   = meta.get("target", "N/A")
    ts       = meta.get("timestamp", "N/A")[:16]

    vuln_rows = "".join([
        f"<tr><td>{v.get('cve','N/A')}</td>"
        f"<td>{v.get('severity','').capitalize()}</td>"
        f"<td>{v.get('cvss_score','N/A')}</td>"
        f"<td style='font-size:11px'>{v.get('name','N/A')[:60]}</td></tr>"
        for v in vulns[:10]
    ])

    port_rows = "".join([
        f"<tr><td>{p.get('port')}</td><td>{p.get('service')}</td>"
        f"<td>{p.get('product','')} {p.get('version','')}</td></tr>"
        for p in ports[:10]
    ])

    html_body = f"""
    <html><body style="font-family:Arial,sans-serif;color:#2c3e50;padding:20px">
      <h2 style="color:#2980b9">🔒 NetPwn Scan Report — {target}</h2>
      <p><strong>Tester:</strong> {meta.get('tester','N/A')} &nbsp;|&nbsp;
         <strong>Date:</strong> {ts}</p>
      <h3>Severity Summary</h3>
      <table border="1" cellpadding="6" style="border-collapse:collapse;width:400px">
        <tr style="background:#c0392b;color:white"><td>Critical</td><td>{severity.get('critical',0)}</td></tr>
        <tr style="background:#e67e22;color:white"><td>High</td><td>{severity.get('high',0)}</td></tr>
        <tr style="background:#f39c12"><td>Medium</td><td>{severity.get('medium',0)}</td></tr>
        <tr style="background:#27ae60;color:white"><td>Low</td><td>{severity.get('low',0)}</td></tr>
      </table>
      <h3>Open Ports</h3>
      <table border="1" cellpadding="6" style="border-collapse:collapse;width:100%">
        <tr style="background:#2980b9;color:white"><th>Port</th><th>Service</th><th>Version</th></tr>
        {port_rows or '<tr><td colspan=3>None</td></tr>'}
      </table>
      <h3>Vulnerabilities</h3>
      <table border="1" cellpadding="6" style="border-collapse:collapse;width:100%">
        <tr style="background:#2980b9;color:white"><th>CVE</th><th>Severity</th><th>CVSS</th><th>Name</th></tr>
        {vuln_rows or '<tr><td colspan=4>None identified</td></tr>'}
      </table>
      <br>
      <p style="font-size:11px;color:#999">Generated by NetPwn Framework — 
         <a href="https://github.com/anveeksh">github.com/anveeksh</a></p>
    </body></html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[NetPwn] Pentest Report — {target} — {ts}"
    msg["From"]    = EMAIL_SENDER
    msg["To"]      = EMAIL_RECIPIENT
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as s:
            s.starttls()
            s.login(EMAIL_SENDER, EMAIL_PASSWORD)
            s.sendmail(EMAIL_SENDER, EMAIL_RECIPIENT, msg.as_string())
        print(f"  [alerts] Email sent to {EMAIL_RECIPIENT}")
    except Exception as e:
        print(f"  [alerts] Email failed: {e}")


# ── Combined alert dispatcher ─────────────────────────────

def send_alerts(results):
    """Call both Slack and email alerts."""
    send_slack_alert(results)
    send_email_alert(results)
