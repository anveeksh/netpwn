import subprocess

def run_enum(target, portscan_results):
    results = {"http": [], "smb": [], "ftp": [], "ssh": [], "banners": []}
    ports = portscan_results.get("open_ports", [])

    for p in ports:
        port, svc = p["port"], p["service"]

        if svc in ("http", "https") or port in ("80", "443", "8080", "8443"):
            results["http"].append(enum_http(target, port))

        elif svc == "ftp" or port == "21":
            results["ftp"].append(enum_ftp(target, port))

        elif svc == "ssh" or port == "22":
            results["ssh"].append({"port": port, "info": p.get("version", "")})

        elif svc in ("netbios-ssn", "microsoft-ds") or port in ("139", "445"):
            results["smb"].append(enum_smb(target))

        results["banners"].append({
            "port": port,
            "service": svc,
            "version": p.get("version", "")
        })

    print(f"  [enum] Enumerated {len(ports)} service(s)")
    return results

def enum_http(target, port):
    try:
        out = subprocess.check_output(
            ["nikto", "-h", f"http://{target}:{port}", "-Format", "txt", "-nointeractive"],
            stderr=subprocess.DEVNULL, text=True, timeout=60
        )
        issues = [l for l in out.splitlines() if l.startswith("+ ")]
        return {"port": port, "findings": issues[:10]}
    except Exception as e:
        return {"port": port, "error": str(e)}

def enum_ftp(target, port):
    try:
        out = subprocess.check_output(
            ["nmap", "-p", port, "--script", "ftp-anon,ftp-bounce", target],
            stderr=subprocess.DEVNULL, text=True
        )
        return {"port": port, "output": out}
    except Exception as e:
        return {"port": port, "error": str(e)}

def enum_smb(target):
    try:
        out = subprocess.check_output(
            ["nmap", "-p", "445", "--script", "smb-vuln*,smb-os-discovery", target],
            stderr=subprocess.DEVNULL, text=True
        )
        return {"output": out}
    except Exception as e:
        return {"error": str(e)}
