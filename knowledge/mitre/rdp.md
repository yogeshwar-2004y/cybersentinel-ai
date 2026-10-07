# Remote Desktop Protocol

## Attack overview
Remote desktop sessions can provide interactive access to other machines. Legitimate support and administration must be distinguished from lateral movement.

## Indicators
New source hosts, unusual logon times, privileged sessions, and remote access across multiple endpoints.

## Detection
Correlate destination logon records, gateway events, VPN sessions, and identity telemetry. Check session ownership and authorized support tickets.

## Mitigation
Use approved gateways, MFA, network restrictions, least privilege, and centralized remote-session auditing.

## MITRE ID
T1021.001

## References
- https://attack.mitre.org/techniques/T1021/001/

## Source note
Original educational summary authored for CyberSentinel AI, 2026-10-07. References are guidance, not live threat feeds. Candidate mappings require analyst validation.
