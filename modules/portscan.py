import subprocess
import xml.etree.ElementTree as ET

def run_portscan(target, flags="-sV -sC -T4"):
    results = {"open_ports": [], "raw_output": ""}
    try:
        cmd = ["nmap"] + flags.split() + ["-oX", "-", target]
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        results["raw_output"] = out
        results["open_ports"] = parse_nmap_xml(out)
        print(f"  [portscan] Found {len(results['open_ports'])} open port(s)")
    except Exception as e:
        results["error"] = str(e)
    return results

def parse_nmap_xml(xml_str):
    ports = []
    try:
        root = ET.fromstring(xml_str)
        for host in root.findall("host"):
            for port in host.findall(".//port"):
                state = port.find("state")
                svc = port.find("service")
                if state is not None and state.get("state") == "open":
                    ports.append({
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "service": svc.get("name") if svc is not None else "unknown",
                        "version": svc.get("version", "") if svc is not None else "",
                        "product": svc.get("product", "") if svc is not None else "",
                    })
    except Exception:
        pass
    return ports
