import subprocess
import socket
import re

def run_recon(target):
    results = {
        "hostname": None,
        "ip": None,
        "alive_hosts": [],
        "dns_records": []
    }

    try:
        ip = socket.gethostbyname(target)
        results["ip"] = ip
        results["hostname"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        results["ip"] = target

    try:
        out = subprocess.check_output(
            ["nmap", "-sn", target, "--open"],
            stderr=subprocess.DEVNULL, text=True
        )
        alive = re.findall(r"Nmap scan report for (.+)", out)
        results["alive_hosts"] = alive
        print(f"  [recon] Found {len(alive)} alive host(s)")
    except Exception as e:
        results["error"] = str(e)

    return results
