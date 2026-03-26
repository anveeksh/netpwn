import ipaddress
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from modules.recon import run_recon
from modules.portscan import run_portscan
from modules.enum import run_enum
from modules.vulnscan import run_vulnscan
from modules.exploit import run_exploit
from modules.cvss import enrich_with_cvss
from modules.report import generate_report

def parse_targets(target_input):
    """
    Accepts:
    - Single IP:       192.168.1.1
    - CIDR range:      192.168.1.0/24
    - IP range:        192.168.1.1-10
    - File path:       targets.txt (one IP per line)
    - Comma separated: 192.168.1.1,192.168.1.2
    """
    targets = []

    # File input
    if os.path.isfile(target_input):
        with open(target_input) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.extend(parse_targets(line))
        return targets

    # Comma separated
    if "," in target_input:
        for t in target_input.split(","):
            targets.extend(parse_targets(t.strip()))
        return targets

    # CIDR range
    try:
        net = ipaddress.ip_network(target_input, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        pass

    # IP range e.g. 192.168.1.1-10
    if "-" in target_input.split(".")[-1]:
        base = ".".join(target_input.split(".")[:-1])
        start, end = target_input.split(".")[-1].split("-")
        return [f"{base}.{i}" for i in range(int(start), int(end) + 1)]

    # Single IP or hostname
    targets.append(target_input)
    return targets


def scan_single(target, config, output_dir, phases):
    """Run full pipeline on a single target."""
    result = {
        "meta": {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "tester": config.get("tester", "Anveeksh M Rao"),
            "engagement": config.get("engagement", "Lab Assessment"),
        },
        "recon": {},
        "portscan": {},
        "enum": {},
        "vulnscan": {},
        "exploit": {},
    }

    try:
        if "recon" in phases:
            result["recon"] = run_recon(target)

        if "portscan" in phases:
            result["portscan"] = run_portscan(target, config.get("scan_type", "-sV -sC -T4"))

        if "enum" in phases:
            result["enum"] = run_enum(target, result["portscan"])

        if "vulnscan" in phases:
            result["vulnscan"] = run_vulnscan(target, result["portscan"])
            # Enrich with CVSS scores
            result["vulnscan"] = enrich_with_cvss(result["vulnscan"])

        if "exploit" in phases:
            result["exploit"] = run_exploit(target, result["vulnscan"], safe_mode=True)

        result["status"] = "completed"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result


def run_multiscan(targets_input, config, output_dir, phases, max_workers=5):
    """
    Scan multiple targets in parallel using ThreadPoolExecutor.
    Returns list of all results.
    """
    targets = parse_targets(targets_input)
    total = len(targets)
    print(f"\n[*] Total targets: {total}")
    print(f"[*] Parallel workers: {max_workers}")
    print(f"[*] Phases: {', '.join(phases)}\n")

    all_results = []
    completed = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_single, t, config, output_dir, phases): t
            for t in targets
        }
        for future in as_completed(futures):
            target = futures[future]
            completed += 1
            try:
                result = future.result()
                all_results.append(result)
                status = result.get("status", "unknown")
                ports = len(result.get("portscan", {}).get("open_ports", []))
                vulns = len(result.get("vulnscan", {}).get("nse_vulns", []))
                print(f"  [{completed}/{total}] {target} — {ports} ports, {vulns} vulns [{status}]")
            except Exception as e:
                print(f"  [{completed}/{total}] {target} — ERROR: {e}")
                all_results.append({"meta": {"target": target}, "status": "error", "error": str(e)})

    # Save combined JSON
    os.makedirs(output_dir, exist_ok=True)
    combined_path = os.path.join(output_dir, "multiscan_results.json")
    with open(combined_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n[*] Combined results saved → {combined_path}")

    # Generate per-target PDF reports
    for result in all_results:
        if result.get("status") == "completed":
            target = result["meta"]["target"].replace(".", "_")
            target_dir = os.path.join(output_dir, f"target_{target}")
            os.makedirs(target_dir, exist_ok=True)
            try:
                pdf = generate_report(result, target_dir)
                print(f"[*] Report → {pdf}")
            except Exception as e:
                print(f"[!] Report failed for {target}: {e}")

    return all_results
