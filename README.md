# NetPwn Framework 🔒
> Advanced Automated Network Penetration Testing Framework

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-lightgrey?style=flat-square)

A modular, Python-based network penetration testing automation framework that chains **recon → port scanning → service enumeration → CVSS-scored vulnerability assessment → report generation** into a single command — with a real-time web dashboard, parallel multi-target scanning, and Slack/email alerting.

Built and tested in an isolated lab environment against Metasploitable 2.

---

## Features

| Feature | Description |
|---|---|
| 🔍 **Recon** | Host discovery via ping sweep + DNS resolution |
| 🚪 **Port Scanning** | Nmap wrapper with full XML parsing |
| 🧩 **Service Enumeration** | HTTP (Nikto), SMB, FTP, SSH banner grabbing |
| 🐛 **Vulnerability Scanning** | NSE scripts + searchsploit CVE lookup |
| 📊 **CVSS Scoring** | Real severity scores fetched from NVD API |
| 📄 **PDF + HTML Reports** | Professional client-ready pentest reports |
| 🖥️ **Web Dashboard** | Real-time Flask UI with charts and vuln tables |
| 📡 **Alerting** | Slack webhook + email alerts on critical findings |
| 🎯 **Multi-target** | Parallel subnet/CIDR/range scanning |
| 🛡️ **Safe Mode** | Exploit identification without execution |

---

## Architecture

```
Target(s)
   │
   ├─► recon.py        → Host discovery, DNS
   ├─► portscan.py     → Nmap XML parsing
   ├─► enum.py         → Nikto, SMB, FTP, SSH
   ├─► vulnscan.py     → NSE + searchsploit
   ├─► cvss.py         → NVD API enrichment
   ├─► exploit.py      → Safe mode exploit check
   └─► report.py       → PDF + HTML generation
            │
            └─► dashboard.py  → Flask web UI
            └─► alerts.py     → Slack + Email
```

---

## Installation

```bash
git clone https://github.com/anveeksh/netpwn
cd netpwn
pip3 install -r requirements.txt
```

**System dependencies:**
```bash
# macOS
brew install nmap nikto

# Kali / Debian
sudo apt install nmap nikto exploitdb
```

---

## Usage

```bash
# Basic scan (recon + portscan + enum + vulnscan)
python3 netpwn.py 192.168.1.100

# With HTML client report
python3 netpwn.py 192.168.1.100 --html

# Full scan including exploit check (lab only)
python3 netpwn.py 192.168.1.100 --full

# Multi-target CIDR scan
python3 netpwn.py 192.168.1.0/24 --multi --workers 10 --html

# IP range scan
python3 netpwn.py 192.168.1.1-20 --multi

# Scan from file
python3 netpwn.py targets.txt --multi

# With Slack/email alerts
python3 netpwn.py 192.168.1.100 --html --alert

# Launch web dashboard
python3 dashboard.py
# Visit http://127.0.0.1:5000
```

---

## Output

Every scan generates:
- `output/scan_results.json` — raw structured data
- `output/pentest_report.pdf` — professional PDF report
- `output/pentest_report.html` — interactive HTML report

---

## Lab Setup

See [lab_setup/lab_setup.md](lab_setup/lab_setup.md) for full guide on setting up Metasploitable 2 as a target using UTM on macOS (M1/M2/M3).

---

## Configuration

Edit `config.yaml`:
```yaml
tester: "Your Name"
engagement: "Client Assessment"
scan_type: "-sV -sC -T4"
safe_mode: true
```

For Slack/email alerts, edit `modules/alerts.py` and fill in:
```python
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/..."
EMAIL_SENDER      = "you@gmail.com"
EMAIL_PASSWORD    = "your-app-password"
EMAIL_RECIPIENT   = "client@company.com"
```

---

## ⚠️ Legal Disclaimer

This tool is for **authorized penetration testing and educational use only**.
Only run against systems you own or have **explicit written permission** to test.
Unauthorized use is illegal under the CFAA and equivalent laws worldwide.

---

## Author

**Anveeksh M Rao (Ish)**
MS Cybersecurity — Northeastern University (Khoury College of Computer Sciences)
Co-Founder, Cyber Tech Associates

[anveekshmrao.com](https://anveekshmrao.com) · [github.com/anveeksh](https://github.com/anveeksh) · [LinkedIn](https://linkedin.com/in/anveeksh)
