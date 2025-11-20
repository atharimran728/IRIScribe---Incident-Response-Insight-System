# Incident Response Report

## Summary
- **Time Range:** 2019-09-25T17:53:24.115013+0000 → 2022-04-17T12:21:05.718655+0000
- **Total Events:** 7035
- **Event Breakdown:** dns (2561), tls (670), fileinfo (54), flow (2996), alert (275), anomaly (183), stats (2), smb (294)

## Observations
- Multiple event types observed including DNS, TLS, HTTP, Flows, Alerts, and File transfers.
- !! Alerts present: see detailed report.
- File transfers detected, some may contain executables.
- Anomaly events logged, worth investigation.

## Recommended Actions
- Block suspicious domains and IPs.
- Isolate impacted hosts.
- Investigate suspicious file downloads.
- Perform threat intel lookups on JA3 hashes, anomalous flows, and rare domains.
