import subprocess
import re
import json

def run_vulnscan(target, portscan_results):
    results = {
        "nse_vulns": [],
        "searchsploit": [],
        "severity_summary": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
    }
    ports = portscan_results.get("open_ports", [])

    # NSE vuln scripts
    try:
        port_list = ",".join([p["port"] for p in ports])
        if port_list:
            out = subprocess.check_output(
                ["nmap", "-p", port_list, "--script", "vuln", target],
                stderr=subprocess.DEVNULL, text=True, timeout=120
            )
            vulns = parse_nse_vulns(out)
            results["nse_vulns"] = vulns
            print(f"  [vulnscan] NSE found {len(vulns)} potential vulnerability/vulnerabilities")
    except Exception as e:
        results["nse_error"] = str(e)

    # Searchsploit lookup per service
    for p in ports:
        query = f"{p.get('product', '')} {p.get('version', '')}".strip()
        if query:
            exploits = searchsploit_lookup(query)
            if exploits:
                results["searchsploit"].append({
                    "service": p["service"],
                    "query": query,
                    "exploits": exploits
                })

    # Severity tally
    for v in results["nse_vulns"]:
        sev = v.get("severity", "low").lower()
        if sev in results["severity_summary"]:
            results["severity_summary"][sev] += 1

    return results

def parse_nse_vulns(nmap_output):
    vulns = []
    for line in nmap_output.splitlines():
        if "VULNERABLE" in line or "CVE-" in line:
            cve = re.search(r"CVE-\d{4}-\d+", line)
            vulns.append({
                "name": line.strip(),
                "cve": cve.group(0) if cve else "N/A",
                "severity": "high" if "CRITICAL" in line.upper() else "medium",
            })
    return vulns

def searchsploit_lookup(query):
    try:
        out = subprocess.check_output(
            ["searchsploit", "--json", query],
            stderr=subprocess.DEVNULL, text=True
        )
        data = json.loads(out)
        exploits = data.get("RESULTS_EXPLOIT", [])
        return [{"title": e["Title"], "path": e["Path"]} for e in exploits[:5]]
    except Exception:
        return []
