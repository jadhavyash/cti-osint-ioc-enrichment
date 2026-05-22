"""
CTI IOC Enrichment Pipeline
Yash Jadhav — github.com/yash-jadhav

Automates IOC enrichment against VirusTotal, AbuseIPDB, and MISP.
Supports IPs, domains, URLs, and file hashes.

Usage:
    python ioc_pipeline.py --ioc 8.8.8.8 --type ip
    python ioc_pipeline.py --file iocs.txt
    python ioc_pipeline.py --ioc malware.exe --type hash --md5 <hash>
"""

import argparse
import json
import time
import hashlib
from datetime import datetime
from pathlib import Path

import requests

# ── Config ────────────────────────────────────────────────────
VT_API_KEY    = "YOUR_VIRUSTOTAL_API_KEY"   # free at virustotal.com
ABUSE_API_KEY = "YOUR_ABUSEIPDB_API_KEY"    # free at abuseipdb.com
MISP_URL      = "https://your-misp-instance.com"
MISP_API_KEY  = "YOUR_MISP_API_KEY"

OUTPUT_DIR = Path("reports")
OUTPUT_DIR.mkdir(exist_ok=True)


# ── VirusTotal ────────────────────────────────────────────────
def vt_lookup(ioc: str, ioc_type: str) -> dict:
    """Query VirusTotal for IP, domain, URL, or file hash."""
    headers = {"x-apikey": VT_API_KEY}
    
    endpoints = {
        "ip":     f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
        "hash":   f"https://www.virustotal.com/api/v3/files/{ioc}",
        "url":    f"https://www.virustotal.com/api/v3/urls/{ioc}",
    }
    
    url = endpoints.get(ioc_type)
    if not url:
        return {"error": f"Unsupported IOC type: {ioc_type}"}
    
    resp = requests.get(url, headers=headers, timeout=15)
    if resp.status_code == 200:
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "source": "VirusTotal",
            "ioc": ioc,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": data.get("reputation", "N/A"),
            "country": data.get("country", "N/A"),
            "verdict": "MALICIOUS" if stats.get("malicious", 0) >= 3 else
                       "SUSPICIOUS" if stats.get("suspicious", 0) >= 2 else "CLEAN",
        }
    return {"source": "VirusTotal", "error": resp.status_code, "ioc": ioc}


# ── AbuseIPDB ─────────────────────────────────────────────────
def abuseipdb_lookup(ip: str) -> dict:
    """Query AbuseIPDB for IP reputation."""
    headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
    
    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers=headers, params=params, timeout=15
    )
    
    if resp.status_code == 200:
        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        return {
            "source": "AbuseIPDB",
            "ioc": ip,
            "abuse_score": score,
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", "N/A"),
            "isp": data.get("isp", "N/A"),
            "usage_type": data.get("usageType", "N/A"),
            "domain": data.get("domain", "N/A"),
            "last_reported": data.get("lastReportedAt", "N/A"),
            "verdict": "MALICIOUS" if score >= 75 else
                       "SUSPICIOUS" if score >= 25 else "CLEAN",
        }
    return {"source": "AbuseIPDB", "error": resp.status_code, "ioc": ip}


# ── MISP ──────────────────────────────────────────────────────
def misp_lookup(ioc: str, ioc_type: str) -> dict:
    """Search MISP threat intelligence platform for IOC."""
    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    payload = {
        "returnFormat": "json",
        "value": ioc,
        "type": ioc_type,
        "limit": 5
    }
    
    resp = requests.post(
        f"{MISP_URL}/attributes/restSearch",
        headers=headers, json=payload, timeout=15, verify=False
    )
    
    if resp.status_code == 200:
        attrs = resp.json().get("response", {}).get("Attribute", [])
        return {
            "source": "MISP",
            "ioc": ioc,
            "matches": len(attrs),
            "events": [a.get("Event", {}).get("info", "N/A") for a in attrs[:3]],
            "verdict": "KNOWN_THREAT" if attrs else "NOT_FOUND",
        }
    return {"source": "MISP", "error": resp.status_code, "ioc": ioc}


# ── Enrichment Orchestrator ───────────────────────────────────
def enrich_ioc(ioc: str, ioc_type: str) -> dict:
    """Run full enrichment pipeline for a single IOC."""
    print(f"[*] Enriching {ioc_type.upper()}: {ioc}")
    result = {
        "ioc": ioc,
        "type": ioc_type,
        "timestamp": datetime.utcnow().isoformat(),
        "enrichments": []
    }
    
    # VirusTotal — all IOC types
    vt = vt_lookup(ioc, ioc_type)
    result["enrichments"].append(vt)
    time.sleep(1)  # rate limit: 4 req/min on free tier

    # AbuseIPDB — IPs only
    if ioc_type == "ip":
        abuse = abuseipdb_lookup(ioc)
        result["enrichments"].append(abuse)

    # MISP — all types (skip if not configured)
    if MISP_API_KEY != "YOUR_MISP_API_KEY":
        misp = misp_lookup(ioc, ioc_type)
        result["enrichments"].append(misp)

    # Overall verdict
    verdicts = [e.get("verdict", "UNKNOWN") for e in result["enrichments"]]
    if "MALICIOUS" in verdicts or "KNOWN_THREAT" in verdicts:
        result["overall_verdict"] = "MALICIOUS"
        result["priority"] = "HIGH"
    elif "SUSPICIOUS" in verdicts:
        result["overall_verdict"] = "SUSPICIOUS"
        result["priority"] = "MEDIUM"
    else:
        result["overall_verdict"] = "CLEAN"
        result["priority"] = "LOW"

    print(f"    Verdict: {result['overall_verdict']} (priority: {result['priority']})")
    return result


def process_ioc_file(filepath: str) -> list:
    """Process a file of IOCs (one per line, format: ioc,type)."""
    results = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            ioc = parts[0].strip()
            ioc_type = parts[1].strip() if len(parts) > 1 else "ip"
            results.append(enrich_ioc(ioc, ioc_type))
    return results


def save_report(results: list | dict, filename: str = None):
    """Save enrichment results to JSON report."""
    if not isinstance(results, list):
        results = [results]
    
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output_file = OUTPUT_DIR / (filename or f"ioc_report_{ts}.json")
    
    report = {
        "generated": datetime.utcnow().isoformat(),
        "total_iocs": len(results),
        "malicious": sum(1 for r in results if r.get("overall_verdict") == "MALICIOUS"),
        "suspicious": sum(1 for r in results if r.get("overall_verdict") == "SUSPICIOUS"),
        "clean": sum(1 for r in results if r.get("overall_verdict") == "CLEAN"),
        "results": results
    }
    
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\n[+] Report saved: {output_file}")
    print(f"    Total: {report['total_iocs']} | Malicious: {report['malicious']} | "
          f"Suspicious: {report['suspicious']} | Clean: {report['clean']}")
    return output_file


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTI IOC Enrichment Pipeline")
    parser.add_argument("--ioc",  help="Single IOC to enrich")
    parser.add_argument("--type", default="ip",
                        choices=["ip","domain","url","hash"],
                        help="IOC type (default: ip)")
    parser.add_argument("--file", help="File with IOCs (format: ioc,type per line)")
    args = parser.parse_args()

    if args.file:
        results = process_ioc_file(args.file)
        save_report(results)
    elif args.ioc:
        result = enrich_ioc(args.ioc, args.type)
        save_report(result)
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()
