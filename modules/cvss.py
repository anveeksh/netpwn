import requests
import time

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_cvss_score(cve_id):
    """
    Fetch CVSS score from NVD API for a given CVE ID.
    Returns dict with score, severity, vector.
    """
    if not cve_id or cve_id == "N/A":
        return {"score": None, "severity": "unknown", "vector": "N/A"}

    try:
        resp = requests.get(
            NVD_API,
            params={"cveId": cve_id},
            timeout=10,
            headers={"User-Agent": "NetPwn-Framework/1.0"}
        )
        if resp.status_code != 200:
            return {"score": None, "severity": "unknown", "vector": "N/A"}

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {"score": None, "severity": "unknown", "vector": "N/A"}

        cve_data = vulns[0].get("cve", {})
        metrics = cve_data.get("metrics", {})

        # Try CVSSv3.1 first, then v3.0, then v2
        for key in ["cvssMetricV31", "cvssMetricV30"]:
            if key in metrics:
                m = metrics[key][0]["cvssData"]
                return {
                    "score": m.get("baseScore"),
                    "severity": m.get("baseSeverity", "unknown").capitalize(),
                    "vector": m.get("vectorString", "N/A"),
                    "version": "3.x"
                }

        if "cvssMetricV2" in metrics:
            m = metrics["cvssMetricV2"][0]["cvssData"]
            return {
                "score": m.get("baseScore"),
                "severity": metrics["cvssMetricV2"][0].get("baseSeverity", "unknown").capitalize(),
                "vector": m.get("vectorString", "N/A"),
                "version": "2.0"
            }

    except Exception as e:
        return {"score": None, "severity": "unknown", "vector": "N/A", "error": str(e)}

    return {"score": None, "severity": "unknown", "vector": "N/A"}


def enrich_with_cvss(vulnscan_results):
    """
    Takes vulnscan results and enriches each vuln with CVSS data from NVD.
    Updates severity_summary based on real CVSS scores.
    """
    vulns = vulnscan_results.get("nse_vulns", [])
    severity_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    print(f"  [cvss] Fetching CVSS scores for {len(vulns)} CVE(s)...")

    for vuln in vulns:
        cve = vuln.get("cve", "N/A")
        cvss = get_cvss_score(cve)
        vuln["cvss_score"] = cvss.get("score", "N/A")
        vuln["cvss_vector"] = cvss.get("vector", "N/A")
        vuln["cvss_version"] = cvss.get("version", "N/A")

        # Override severity with real CVSS data
        score = cvss.get("score")
        if score is not None:
            if score >= 9.0:
                vuln["severity"] = "critical"
            elif score >= 7.0:
                vuln["severity"] = "high"
            elif score >= 4.0:
                vuln["severity"] = "medium"
            else:
                vuln["severity"] = "low"
        
        sev = vuln.get("severity", "low").lower()
        if sev in severity_summary:
            severity_summary[sev] += 1

        # NVD rate limit — 6 requests per 30 seconds without API key
        time.sleep(6)

    vulnscan_results["nse_vulns"] = vulns
    vulnscan_results["severity_summary"] = severity_summary
    print(f"  [cvss] Enrichment complete — {severity_summary}")
    return vulnscan_results


def cvss_to_label(score):
    """Convert numeric CVSS score to text label."""
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    else:
        return "Low"
