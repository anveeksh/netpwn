#!/usr/bin/env python3
"""
NetPwn Framework — Advanced Automated Network Penetration Testing Tool
Author: Anveeksh M Rao (Ish)
GitHub: github.com/anveeksh/netpwn-framework
"""

import argparse
import json
import sys
import os
import yaml
from datetime import datetime

from modules.recon import run_recon
from modules.portscan import run_portscan
from modules.enum import run_enum
from modules.vulnscan import run_vulnscan
from modules.exploit import run_exploit
from modules.cvss import enrich_with_cvss
from modules.report import generate_report
from modules.htmlreport import generate_html_report
from modules.alerts import send_alerts
from modules.multitarget import run_multiscan

BANNER = """
  _   _      _   ____                      
 | \\ | | ___| |_|  _ \\ _      ___ __  
 |  \\| |/ _ \\ __| |_) \\ \\ /\\ / / '_ \\ 
 | |\\  |  __/ |_|  __/ \\ V  V /| | | |
 |_| \\_|\\___|\\__|_|     \\_/\\_/ |_| |_|
 
 Advanced Network Pentest Framework v2.0
 Author: Anveeksh M Rao | github.com/anveeksh
"""

def load_config(path="config.yaml"):
    with open(path) as f:
        return yaml.safe_load(f)

def run_pipeline(target, config, phases, output_dir, html=False, alert=False):
    results = {
        "meta": {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "tester": config.get("tester", "Anveeksh M Rao"),
            "engagement": config.get("engagement", "Internal Lab Assessment"),
        },
        "recon":    {},
        "portscan": {},
        "enum":     {},
        "vulnscan": {},
        "exploit":  {},
    }

    print(f"\n[*] Target   : {target}")
    print(f"[*] Phases   : {', '.join(phases)}")
    print(f"[*] HTML report: {'yes' if html else 'no'}")
    print(f"[*] Alerting : {'yes' if alert else 'no'}\n")

    if "recon" in phases:
        print("[+] Phase 1: Recon")
        results["recon"] = run_recon(target)

    if "portscan" in phases:
        print("[+] Phase 2: Port Scan")
        results["portscan"] = run_portscan(target, config.get("scan_type", "-sV -sC -T4"))

    if "enum" in phases:
        print("[+] Phase 3: Service Enumeration")
        results["enum"] = run_enum(target, results["portscan"])

    if "vulnscan" in phases:
        print("[+] Phase 4: Vulnerability Scan")
        results["vulnscan"] = run_vulnscan(target, results["portscan"])
        print("[+] Phase 4b: CVSS Enrichment")
        results["vulnscan"] = enrich_with_cvss(results["vulnscan"])

    if "exploit" in phases:
        print("[+] Phase 5: Exploitation (Safe Mode)")
        results["exploit"] = run_exploit(target, results["vulnscan"], safe_mode=True)

    # Save raw JSON
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, "scan_results.json")
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[*] Raw results  → {json_path}")

    # PDF report
    print("[+] Generating PDF report...")
    pdf_path = generate_report(results, output_dir)
    print(f"[*] PDF report   → {pdf_path}")

    # HTML report
    if html:
        print("[+] Generating HTML report...")
        html_path = generate_html_report(results, output_dir)
        print(f"[*] HTML report  → {html_path}")

    # Alerts
    if alert:
        print("[+] Sending alerts...")
        send_alerts(results)

    return results

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="NetPwn v2.0 — Advanced Network Penetration Testing Framework"
    )
    parser.add_argument("target",
        help="Single IP, CIDR (192.168.1.0/24), range (192.168.1.1-10), file, or comma-separated IPs")
    parser.add_argument("--config",  default="config.yaml")
    parser.add_argument("--output",  default="./output")
    parser.add_argument("--phases",  nargs="+",
        default=["recon", "portscan", "enum", "vulnscan"],
        choices=["recon", "portscan", "enum", "vulnscan", "exploit"])
    parser.add_argument("--full",    action="store_true",
        help="Run all phases including exploit")
    parser.add_argument("--multi",   action="store_true",
        help="Enable multi-target parallel scanning")
    parser.add_argument("--workers", type=int, default=5,
        help="Parallel workers for multi-target scan (default: 5)")
    parser.add_argument("--html",    action="store_true",
        help="Generate HTML client report")
    parser.add_argument("--alert",   action="store_true",
        help="Send Slack/email alerts on findings")

    args   = parser.parse_args()
    config = load_config(args.config)
    phases = ["recon","portscan","enum","vulnscan","exploit"] if args.full else args.phases

    # Exploit confirmation
    if "exploit" in phases:
        confirm = input("\n[!] Exploit phase enabled. Only run against systems you own.\nConfirm? (yes/no): ")
        if confirm.lower() != "yes":
            print("[-] Aborted.")
            sys.exit(0)

    os.makedirs(args.output, exist_ok=True)

    # Multi-target mode
    if args.multi:
        print(f"[*] Multi-target mode — workers: {args.workers}")
        run_multiscan(args.target, config, args.output, phases, max_workers=args.workers)
    else:
        run_pipeline(args.target, config, phases, args.output,
                     html=args.html, alert=args.alert)

    print("\n[✓] NetPwn scan complete.")
    print(f"[*] View results: python3 dashboard.py\n")

if __name__ == "__main__":
    main()
