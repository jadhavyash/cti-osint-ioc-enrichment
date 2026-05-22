# CTI / OSINT IOC Enrichment Pipeline

**Automated cyber threat intelligence pipeline — enriches IOCs (IPs, domains, URLs, hashes) against VirusTotal, AbuseIPDB, and MISP using Python.**

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal_API-394EFF?style=flat)
![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB_API-CC0000?style=flat)
![MISP](https://img.shields.io/badge/MISP_Integration-007DC6?style=flat)

## What It Does

```
Input IOC (IP/domain/hash/URL)
        │
        ├──▶ VirusTotal API    → malicious/clean verdict + engine count
        ├──▶ AbuseIPDB API     → abuse confidence score + report history
        └──▶ MISP              → known threat actor attribution
                │
                ▼
        Aggregated JSON Report
        Priority: HIGH / MEDIUM / LOW
        Overall Verdict: MALICIOUS / SUSPICIOUS / CLEAN
```

## Results

| Metric | Value |
|--------|-------|
| IOC triage time reduction | 60% vs manual lookup |
| Supported IOC types | IP, domain, URL, MD5/SHA256 hash |
| Threat feed sources | VirusTotal, AbuseIPDB, MISP |
| Output format | JSON report + console summary |

## Quick Start

```bash
git clone https://github.com/yash-jadhav/cti-osint-ioc-enrichment
cd cti-osint-ioc-enrichment
pip install -r requirements.txt

# Add API keys to ioc_pipeline.py
# VT_API_KEY    = "your_key"   # free at virustotal.com
# ABUSE_API_KEY = "your_key"   # free at abuseipdb.com

# Enrich a single IP
python ioc_pipeline.py --ioc 8.8.8.8 --type ip

# Enrich a domain
python ioc_pipeline.py --ioc malware-c2.example.com --type domain

# Bulk enrich from file
python ioc_pipeline.py --file sample-iocs/malicious_ips.txt
```

## Sample Output

```json
{
  "ioc": "185.220.101.45",
  "type": "ip",
  "timestamp": "2025-11-15T14:32:11",
  "overall_verdict": "MALICIOUS",
  "priority": "HIGH",
  "enrichments": [
    {
      "source": "VirusTotal",
      "malicious": 12,
      "suspicious": 2,
      "verdict": "MALICIOUS",
      "country": "DE",
      "reputation": -85
    },
    {
      "source": "AbuseIPDB",
      "abuse_score": 100,
      "total_reports": 847,
      "isp": "Tor Exit Node",
      "verdict": "MALICIOUS"
    }
  ]
}
```

## IOC Input File Format

```
# iocs.txt — one IOC per line (ioc,type)
185.220.101.45,ip
malware-c2.example.com,domain
44d88612fea8a8f36de82e1278abb02f,hash
http://phishing.example.com/login,url
```

## Requirements

```
requests>=2.31.0
```

Free API keys:
- VirusTotal: https://www.virustotal.com/gui/my-apikey (4 req/min free)
- AbuseIPDB: https://www.abuseipdb.com/account/api (1000 req/day free)
