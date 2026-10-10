# Methodology and analyst safeguards

1. Define the intelligence question and approved indicators.
2. Validate indicator type and syntax before collection.
3. Query configured providers; record errors and unavailable sources explicitly.
4. Aggregate source findings using transparent heuristic thresholds.
5. Produce JSON evidence and a Markdown analyst briefing.
6. Validate internal exposure and business relevance before escalation or response.
7. Seek feedback and update collection requirements and source quality rules.

## Known limitations

- No automatic attribution or ATT&CK mapping: an IOC alone cannot establish an actor or technique.
- The MISP lookup searches matching attributes; it does not verify the trustworthiness of the associated event.
- No API keys means unknown results. Rate limits are handled for some transient failures, but no persistent quota management exists.
- API data can be stale, incomplete, or conflicting. Source counts are not calibrated analytic confidence.
- No measured performance claims are made. Benchmark manually and automated runs on the same labeled IOC set before publishing a percentage improvement.
- The current CLI accepts only IOC,type CSV rows; it is not a full SIEM or TIP.
