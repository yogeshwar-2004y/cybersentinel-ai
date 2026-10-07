# Web Attack Triage

## Attack overview
Web alerts may represent attempted exploitation, blocked activity, or benign scanners. Successful compromise requires evidence beyond a suspicious request.

## Indicators
Repeated error responses, WAF alerts, abnormal database operations, and unexpected server-side processes.

## Detection
Correlate request identifiers across proxy, application, database, and endpoint logs. Establish whether the application processed dangerous input.

## Mitigation
Correct vulnerable code, apply tested compensating controls, restrict privileges, and validate the remediation through authorized testing.

## MITRE ID
No direct technique asserted. Require behavioral evidence before assigning ATT&CK.

## References
- https://csrc.nist.gov/pubs/sp/800/61/r3/final

## Source note
Original educational summary authored for CyberSentinel AI, 2026-10-07. References are guidance, not live threat feeds. Candidate mappings require analyst validation.
