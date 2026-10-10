"""IOC validation, source enrichment, evidence assessment, and reporting."""
import base64
import hashlib
import ipaddress
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import requests


def now():
    return datetime.now(timezone.utc).isoformat()


def validate(ioc, kind):
    ioc = ioc.strip()
    if kind == "ip":
        return str(ipaddress.ip_address(ioc))
    if kind == "domain":
        if len(ioc) > 253 or not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+", ioc):
            raise ValueError("Invalid domain")
        return ioc.lower()
    if kind == "url":
        u = urlsplit(ioc)
        if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
            raise ValueError("Expected HTTP(S) URL without embedded credentials")
        return ioc
    if kind == "hash":
        if len(ioc) not in (32, 40, 64) or not re.fullmatch(r"[a-fA-F0-9]+", ioc):
            raise ValueError("Expected MD5, SHA1, or SHA256 hex digest")
        return ioc.lower()
    raise ValueError("Unsupported IOC type")


def request_json(method, url, *, headers, params=None, payload=None, verify=True, retries=2, session=None):
    client = session or requests
    for attempt in range(retries + 1):
        try:
            r = client.request(method, url, headers=headers, params=params, json=payload, timeout=15, verify=verify)
            if r.status_code in (429, 500, 502, 503, 504) and attempt < retries:
                retry_after = r.headers.get("Retry-After", "")
                delay = min(float(retry_after), 60) if retry_after.isdigit() else min(2 ** attempt, 8)
                time.sleep(delay)
                continue
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}"}
            try:
                return {"data": r.json()}
            except ValueError:
                return {"error": "Invalid JSON response"}
        except requests.RequestException as exc:
            if attempt == retries:
                return {"error": type(exc).__name__}
            time.sleep(min(2 ** attempt, 8))
    return {"error": "Request unsuccessful"}


def virustotal(ioc, kind, key, session=None):
    if not key:
        return {"source": "VirusTotal", "status": "not_configured"}
    if kind == "url":
        identifier = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
        path = f"urls/{identifier}"
    else:
        plural = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}[kind]
        path = f"{plural}/{ioc}"
    response = request_json("GET", f"https://www.virustotal.com/api/v3/{path}", headers={"x-apikey": key}, session=session)
    if "error" in response:
        return {"source": "VirusTotal", "status": "error", "error": response["error"]}
    attributes = response["data"].get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    malicious, suspicious = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
    verdict = "malicious" if malicious >= 3 else "suspicious" if malicious > 0 or suspicious >= 2 else "no_detection"
    return {"source": "VirusTotal", "status": "ok", "verdict": verdict, "malicious_engines": malicious,
            "suspicious_engines": suspicious, "last_analysis_date": attributes.get("last_analysis_date")}


def abuseipdb(ioc, key, session=None):
    if not key:
        return {"source": "AbuseIPDB", "status": "not_configured"}
    response = request_json("GET", "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": key, "Accept": "application/json"},
        params={"ipAddress": ioc, "maxAgeInDays": 90}, session=session)
    if "error" in response:
        return {"source": "AbuseIPDB", "status": "error", "error": response["error"]}
    data = response["data"].get("data", {})
    score = int(data.get("abuseConfidenceScore", 0))
    return {"source": "AbuseIPDB", "status": "ok", "verdict": "malicious" if score >= 75 else "suspicious" if score >= 25 else "no_detection",
            "abuse_confidence_score": score, "total_reports": data.get("totalReports", 0), "last_reported": data.get("lastReportedAt")}


def misp(ioc, kind, url, key, ca_bundle=None, session=None):
    if not url or not key:
        return {"source": "MISP", "status": "not_configured"}
    types = {"ip": ["ip-src", "ip-dst", "ip-src|port", "ip-dst|port"],
             "domain": ["domain", "hostname"], "url": ["url"],
             "hash": [{32: "md5", 40: "sha1", 64: "sha256"}[len(ioc)]]}[kind]
    response = request_json("POST", f"{url.rstrip('/')}/attributes/restSearch",
        headers={"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"},
        payload={"returnFormat": "json", "value": ioc, "type": types, "limit": 20},
        verify=ca_bundle or True, session=session)
    if "error" in response:
        return {"source": "MISP", "status": "error", "error": response["error"]}
    raw = response["data"].get("response", {})
    attrs = raw.get("Attribute", []) if isinstance(raw, dict) else raw if isinstance(raw, list) else []
    matches = [a for a in attrs if a.get("value", "").lower() == ioc.lower() and a.get("type") in types]
    return {"source": "MISP", "status": "ok", "verdict": "known_indicator" if matches else "no_detection",
            "matches": len(matches), "event_ids": sorted(set(str(a.get("event_id")) for a in matches if a.get("event_id")))}


def assess(sources):
    good = [s for s in sources if s.get("status") == "ok"]
    if not good:
        return {"verdict": "unknown", "confidence": "none", "priority": "review", "reason": "No successful intelligence lookups"}
    values = [s.get("verdict") for s in good]
    if "malicious" in values or "known_indicator" in values:
        verdict, priority = "malicious", "high"
    elif "suspicious" in values:
        verdict, priority = "suspicious", "medium"
    else:
        verdict, priority = "no_detection", "low"
    positive = sum(v in ("malicious", "known_indicator", "suspicious") for v in values)
    confidence = "moderate" if positive >= 2 else "low" if positive else "not_assessed"
    if any(s.get("status") == "error" for s in sources) and verdict == "no_detection":
        confidence = "low"
    return {"verdict": verdict, "confidence": confidence, "priority": priority,
            "reason": "Rule-based assessment of external sources; not proof of compromise or attribution"}


def enrich(ioc, kind, *, config=None, session=None):
    ioc = validate(ioc, kind)
    cfg = config if config is not None else os.environ
    sources = [virustotal(ioc, kind, cfg.get("VT_API_KEY"), session)]
    if kind == "ip":
        sources.append(abuseipdb(ioc, cfg.get("ABUSE_API_KEY"), session))
    sources.append(misp(ioc, kind, cfg.get("MISP_URL"), cfg.get("MISP_API_KEY"), cfg.get("MISP_CA_BUNDLE"), session))
    return {"ioc": ioc, "type": kind, "timestamp": now(), "sources": sources, "assessment": assess(sources)}


def build_report(results):
    return {"generated": now(), "total_iocs": len(results), "counts": {v: sum(r["assessment"]["verdict"] == v for r in results)
            for v in ("malicious", "suspicious", "no_detection", "unknown")}, "results": results}


def executive_markdown(report):
    counts = report["counts"]
    lines = ["# Cyber Threat Intelligence Assessment", "", f"Generated: {report['generated']}",
             "", "## Executive summary", f"Reviewed {report['total_iocs']} indicators. "
             f"{counts['malicious']} flagged malicious, {counts['suspicious']} suspicious, "
             f"{counts['no_detection']} with no detections, and {counts['unknown']} unknown.",
             "", "## Evidence and analytic limitations",
             "These results are external-source enrichment, not confirmation of internal exposure or threat actor attribution.",
             "No detection does not mean an indicator is safe. Confidence labels are prototype heuristics, not calibrated probabilities.",
             "", "## Indicator findings"]
    for r in report["results"]:
        a = r["assessment"]
        lines.extend([f"### {r['type']}: `{r['ioc']}`", f"- Verdict: {a['verdict']}; confidence: {a['confidence']}; priority: {a['priority']}"])
        for s in r["sources"]:
            lines.append(f"- {s['source']}: {s['status']} / {s.get('verdict', 'not available')}")
    lines.extend(["", "## Recommended next steps", "- Validate flagged indicators against internal DNS, endpoint, and authentication telemetry.",
                  "- Review source reliability, indicator freshness, and false positives before taking blocking action.",
                  "- Escalate confirmed exposure using incident response procedures.", "", "## ATT&CK and attribution", 
                  "No ATT&CK technique or threat actor is assigned without independent behavioral evidence."])
    return "\n".join(lines) + "\n"


def save(report, out_dir="reports"):
    path = Path(out_dir)
    path.mkdir(parents=True, exist_ok=True)
    suffix = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    json_file = path / f"cti_{suffix}.json"
    md_file = path / f"cti_{suffix}.md"
    json_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_file.write_text(executive_markdown(report), encoding="utf-8")
    return json_file, md_file
