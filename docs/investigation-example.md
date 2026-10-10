# End-to-end IOC investigation: 8.8.8.8

> **Scope:** Real enrichment results from a local run on 2026-10-10. This is a benign, publicly known DNS resolver used to demonstrate the workflow; it is **not** presented as an attack or confirmed security incident.

## 1. Intelligence requirement

Can the pipeline enrich an IPv4 indicator from independent sources, distinguish a low-risk reputation result from an API failure, and produce a reviewable analyst report?

## 2. Collection and validation

Input: `8.8.8.8` (IPv4). The command used was:

```powershell
.\.venv\Scripts\python.exe -m cti_pipeline --ioc 8.8.8.8 --type ip
```

The pipeline queried VirusTotal and AbuseIPDB using locally configured credentials. MISP was not configured, and no internal network, DNS, endpoint, or authentication logs were collected.

## 3. Evidence from the live run

| Source | Observed result | Interpretation |
|---|---|---|
| VirusTotal | API status `ok`; 0 malicious engines; 0 suspicious engines | No detection reported by this source at lookup time |
| AbuseIPDB | API status `ok`; abuse confidence score 0; 235 historical reports | Score was zero despite report history; report count alone is not proof of current malicious activity |
| MISP | `not_configured` | No MISP intelligence was collected; do not treat as a clean result |

See [sample-report.json](../examples/sample-report.json) for the source response fields preserved by the pipeline. The public sample contains no API keys or authorization headers.

## 4. Analysis and prioritization

The pipeline produced `no_detection`, with `low` priority and confidence `not_assessed`. This is a rule-based reputation assessment, not an independently validated safety determination. The IOC is Google Public DNS, which provides benign context, but any investigation must still examine why a system communicated with it.

## 5. Analyst decision

No blocking action is justified from these reputation results alone. If this IOC arose in a real alert, correlate the relevant timestamps and host/process context with approved internal DNS, network, and endpoint telemetry. Escalate only if behavioral evidence supports malicious use.

## 6. Reporting and limitations

The pipeline saved structured JSON and Markdown reports. This demonstration validates successful live enrichment of one IPv4 IOC, not malicious IOC detection accuracy, MISP connectivity, threat actor attribution, or automatic MITRE ATT&CK mapping. API results and scores can change over time.

## 7. Potential follow-up

- Test an authorized, known-malicious *synthetic or safely documented* IOC in offline mocks to validate high-priority verdict logic without publishing harmful or sensitive indicators.
- Add explicit handling and unit tests for HTTP 429, timeouts, and unavailable intelligence sources.
- When a MISP server is available, verify connectivity and capture only non-sensitive event context with proper attribution caveats.
