# Cloud Identity Investigation

## Attack overview
Cloud control planes can be accessed through legitimate identities. Compromise hypotheses require authentication, authorization, and operation history.

## Indicators
New access keys, unusual role assumption, privileged configuration changes, and unfamiliar API activity.

## Detection
Correlate identity sessions, API audit logs, source networks, role changes, and resource access. Distinguish automation from interactive use.

## Mitigation
Reduce standing privileges, review credential exposure, protect audit logs, and rotate confirmed exposed keys under incident procedures.

## MITRE ID
T1078

## References
- https://csrc.nist.gov/pubs/sp/800/61/r3/final
- https://attack.mitre.org/techniques/T1078/

## Source note
Original educational summary authored for CyberSentinel AI, 2026-10-07. References are guidance, not live threat feeds. Candidate mappings require analyst validation.
