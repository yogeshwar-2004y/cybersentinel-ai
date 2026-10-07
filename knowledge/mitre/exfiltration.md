# Exfiltration Over Alternative Protocol

## Attack overview
Stolen data may leave through a protocol different from an existing command channel. Outbound byte volume alone cannot establish theft or this specific mapping.

## Indicators
Unusual outbound volume, unfamiliar destinations, unexpected transfer protocols, and sensitive file access before transfer.

## Detection
Inspect flows, proxy records, data classification, and approved transfer jobs. Confirm the protocol and data origin before asserting exfiltration.

## Mitigation
Apply approved egress restrictions, data loss monitoring, destination controls, and least-privilege data access. Preserve transfer evidence.

## MITRE ID
T1048

## References
- https://attack.mitre.org/techniques/T1048/

## Source note
Original educational summary authored for CyberSentinel AI, 2026-10-07. References are guidance, not live threat feeds. Candidate mappings require analyst validation.
