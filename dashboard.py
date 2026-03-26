#!/usr/bin/env python3
"""
NetPwn Web Dashboard — Flask-based UI to view scan results
Run: python3 dashboard.py
Visit: http://127.0.0.1:5000
"""

from flask import Flask, render_template_string, jsonify, request, send_file
import json, os, glob
from datetime import datetime

app = Flask(__name__)
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")

# ── helpers ──────────────────────────────────────────────

def load_all_results():
    results = []
    # single scan
    p = os.path.join(OUTPUT_DIR, "scan_results.json")
    if os.path.exists(p):
        with open(p) as f:
            results.append(json.load(f))
    # multi-scan
    p2 = os.path.join(OUTPUT_DIR, "multiscan_results.json")
    if os.path.exists(p2):
        with open(p2) as f:
            results.extend(json.load(f))
    # per-target subdirs
    for fp in glob.glob(os.path.join(OUTPUT_DIR, "target_*", "scan_results.json")):
        with open(fp) as f:
            results.append(json.load(f))
    return results

def summary_stats(results):
    total_targets = len(results)
    total_ports   = sum(len(r.get("portscan",{}).get("open_ports",[])) for r in results)
    total_vulns   = sum(len(r.get("vulnscan",{}).get("nse_vulns",[])) for r in results)
    sev = {"critical":0,"high":0,"medium":0,"low":0}
    for r in results:
        s = r.get("vulnscan",{}).get("severity_summary",{})
        for k in sev:
            sev[k] += s.get(k, 0)
    return total_targets, total_ports, total_vulns, sev

# ── HTML template ────────────────────────────────────────

DASH_HTML = """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetPwn Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3;min-height:100vh}
  .topbar{background:#161b22;border-bottom:1px solid #30363d;padding:14px 30px;
          display:flex;align-items:center;justify-content:space-between}
  .topbar h1{font-size:20px;color:#58a6ff}
  .topbar span{font-size:12px;color:#8b949e}
  .container{max-width:1200px;margin:30px auto;padding:0 20px}
  .stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:28px}
  .stat-card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px;text-align:center}
  .stat-card .num{font-size:36px;font-weight:700}
  .stat-card .lbl{font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;margin-top:4px}
  .card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:24px;margin-bottom:24px}
  .card h2{font-size:16px;color:#58a6ff;margin-bottom:16px;border-left:3px solid #58a6ff;padding-left:10px}
  .charts{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:28px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{background:#21262d;color:#8b949e;padding:10px 12px;text-align:left;font-weight:500;
     border-bottom:1px solid #30363d;font-size:11px;text-transform:uppercase;letter-spacing:.5px}
  td{padding:10px 12px;border-bottom:1px solid #21262d}
  tr:hover td{background:#1c2128}
  .badge{display:inline-block;padding:2px 10px;border-radius:10px;font-size:11px;font-weight:600;color:white}
  .badge-critical{background:#da3633} .badge-high{background:#d29922}
  .badge-medium{background:#9e6a03;color:#fff} .badge-low{background:#238636}
  .badge-unknown{background:#484f58}
  .tag{display:inline-block;background:#21262d;color:#8b949e;border-radius:4px;
       padding:2px 8px;font-size:11px;margin:2px}
  .empty{color:#8b949e;font-size:13px;padding:20px 0;text-align:center}
  .refresh{background:#238636;color:white;border:none;padding:8px 16px;border-radius:6px;
           cursor:pointer;font-size:13px}
  .refresh:hover{background:#2ea043}
</style>
</head><body>

<div class="topbar">
  <h1>🔒 NetPwn Dashboard</h1>
  <div>
    <span id="lastupdate">Loading...</span>
    <button class="refresh" onclick="loadData()" style="margin-left:12px">↻ Refresh</button>
  </div>
</div>

<div class="container">
  <div class="stat-grid">
    <div class="stat-card"><div class="num" id="s-targets" style="color:#58a6ff">—</div><div class="lbl">Targets Scanned</div></div>
    <div class="stat-card"><div class="num" id="s-ports"   style="color:#3fb950">—</div><div class="lbl">Open Ports</div></div>
    <div class="stat-card"><div class="num" id="s-vulns"   style="color:#d29922">—</div><div class="lbl">Vulnerabilities</div></div>
    <div class="stat-card"><div class="num" id="s-crit"    style="color:#da3633">—</div><div class="lbl">Critical Findings</div></div>
  </div>

  <div class="charts">
    <div class="card"><h2>Severity Distribution</h2><canvas id="sevChart" height="200"></canvas></div>
    <div class="card"><h2>Ports per Target</h2><canvas id="portChart" height="200"></canvas></div>
  </div>

  <div class="card">
    <h2>Scanned Targets</h2>
    <table>
      <thead><tr><th>Target</th><th>Ports</th><th>Vulns</th><th>Risk</th><th>Services</th><th>Timestamp</th></tr></thead>
      <tbody id="target-tbody"><tr><td colspan="6" class="empty">Loading...</td></tr></tbody>
    </table>
  </div>

  <div class="card">
    <h2>All Vulnerabilities</h2>
    <table>
      <thead><tr><th>Target</th><th>CVE</th><th>Name</th><th>Severity</th><th>CVSS</th></tr></thead>
      <tbody id="vuln-tbody"><tr><td colspan="5" class="empty">Loading...</td></tr></tbody>
    </table>
  </div>
</div>

<script>
let sevChart, portChart;

function riskLabel(sev){
  let s = (sev.critical||0)*10+(sev.high||0)*7+(sev.medium||0)*4;
  if(s>=20) return ['Critical','badge-critical'];
  if(s>=10) return ['High','badge-high'];
  if(s>=5)  return ['Medium','badge-medium'];
  return ['Low','badge-low'];
}

async function loadData(){
  const r = await fetch('/api/results');
  const data = await r.json();
  const stats = data.stats;

  document.getElementById('s-targets').textContent = stats.total_targets;
  document.getElementById('s-ports').textContent   = stats.total_ports;
  document.getElementById('s-vulns').textContent   = stats.total_vulns;
  document.getElementById('s-crit').textContent    = stats.severity.critical||0;
  document.getElementById('lastupdate').textContent = 'Updated: '+new Date().toLocaleTimeString();

  // Severity chart
  const sev = stats.severity;
  const sevData = {
    labels:['Critical','High','Medium','Low'],
    datasets:[{data:[sev.critical||0,sev.high||0,sev.medium||0,sev.low||0],
      backgroundColor:['#da3633','#d29922','#9e6a03','#238636'],borderWidth:0}]
  };
  if(sevChart) sevChart.destroy();
  sevChart = new Chart(document.getElementById('sevChart'),{type:'doughnut',data:sevData,
    options:{plugins:{legend:{labels:{color:'#e6edf3'}}}}});

  // Port chart
  const labels = data.results.map(r=>r.meta?.target||'?');
  const portCounts = data.results.map(r=>r.portscan?.open_ports?.length||0);
  const portData = {labels,datasets:[{label:'Open Ports',data:portCounts,
    backgroundColor:'#1f6feb',borderRadius:4}]};
  if(portChart) portChart.destroy();
  portChart = new Chart(document.getElementById('portChart'),{type:'bar',data:portData,
    options:{plugins:{legend:{display:false}},scales:{
      x:{ticks:{color:'#8b949e'},grid:{color:'#21262d'}},
      y:{ticks:{color:'#8b949e'},grid:{color:'#21262d'}}}}});

  // Target rows
  const tbody = document.getElementById('target-tbody');
  if(!data.results.length){tbody.innerHTML='<tr><td colspan="6" class="empty">No scan results found. Run a scan first.</td></tr>';return;}
  tbody.innerHTML = data.results.map(r=>{
    const target = r.meta?.target||'N/A';
    const ports  = r.portscan?.open_ports?.length||0;
    const vulns  = r.vulnscan?.nse_vulns?.length||0;
    const sev2   = r.vulnscan?.severity_summary||{};
    const [rl,rc]= riskLabel(sev2);
    const services = [...new Set((r.portscan?.open_ports||[]).map(p=>p.service))].slice(0,4);
    const ts = r.meta?.timestamp?.slice(0,16)||'N/A';
    return `<tr>
      <td><strong>${target}</strong></td>
      <td>${ports}</td><td>${vulns}</td>
      <td><span class="badge ${rc}">${rl}</span></td>
      <td>${services.map(s=>`<span class="tag">${s}</span>`).join('')}</td>
      <td style="color:#8b949e;font-size:12px">${ts}</td>
    </tr>`;
  }).join('');

  // Vuln rows
  const vbody = document.getElementById('vuln-tbody');
  const allVulns = [];
  data.results.forEach(r=>{
    (r.vulnscan?.nse_vulns||[]).forEach(v=>{
      allVulns.push({target:r.meta?.target||'N/A',...v});
    });
  });
  if(!allVulns.length){vbody.innerHTML='<tr><td colspan="5" class="empty">No vulnerabilities found.</td></tr>';return;}
  vbody.innerHTML = allVulns.map(v=>{
    const sev3 = v.severity||'unknown';
    return `<tr>
      <td>${v.target}</td>
      <td><a href="https://nvd.nist.gov/vuln/detail/${v.cve}" target="_blank" style="color:#58a6ff">${v.cve||'N/A'}</a></td>
      <td style="font-size:12px">${v.name||'N/A'}</td>
      <td><span class="badge badge-${sev3}">${sev3}</span></td>
      <td>${v.cvss_score||'N/A'}</td>
    </tr>`;
  }).join('');
}

loadData();
setInterval(loadData, 30000);
</script>
</body></html>
"""

# ── routes ───────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(DASH_HTML)

@app.route("/api/results")
def api_results():
    results = load_all_results()
    t, p, v, sev = summary_stats(results)
    return jsonify({
        "results": results,
        "stats": {
            "total_targets": t,
            "total_ports":   p,
            "total_vulns":   v,
            "severity":      sev,
        }
    })

@app.route("/api/report/<path:target>")
def get_report(target):
    safe = target.replace(".", "_")
    paths = [
        os.path.join(OUTPUT_DIR, "pentest_report.pdf"),
        os.path.join(OUTPUT_DIR, f"target_{safe}", "pentest_report.pdf"),
        os.path.join(OUTPUT_DIR, "pentest_report.html"),
        os.path.join(OUTPUT_DIR, f"target_{safe}", "pentest_report.html"),
    ]
    for p in paths:
        if os.path.exists(p):
            return send_file(p)
    return jsonify({"error": "Report not found"}), 404

if __name__ == "__main__":
    print("\n[*] NetPwn Dashboard starting...")
    print("[*] Visit: http://127.0.0.1:5000\n")
    app.run(debug=True, port=5000)
