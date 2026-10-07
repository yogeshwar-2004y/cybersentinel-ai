# Indicator Removal

## Attack overview
Attackers may delete or alter artifacts to hinder reconstruction of activity. Log retention failures may produce similar gaps.

## Indicators
Unexpected log clearing, telemetry outages, missing files, and suspicious administrative actions.

## Detection
Correlate collector health, endpoint activity, retention policies, and independent network records. Verify the cause of missing evidence.

## Mitigation
Centralize immutable audit records, alert on log-clearing actions, protect collector configuration, and investigate privileged access.

## MITRE ID
T1070

## References
- https://attack.mitre.org/techniques/T1070/

## Source note
Original educational summary authored for CyberSentinel AI, 2026-10-07. References are guidance, not live threat feeds. Candidate mappings require analyst validation.
