# Remote Services

## Attack overview
Remote services may allow an attacker to move between systems using stolen or misused credentials. A remote connection is not inherently malicious.

## Indicators
New host-to-host authentication paths, unusual administrator usage, remote service creation, and multi-host sessions.

## Detection
Build a timeline across identity, endpoint, and network records. Compare remote access against administrative baselines.

## Mitigation
Restrict east-west access, segment administrative paths, enforce least privilege, and review credentials associated with confirmed movement.

## MITRE ID
T1021

## References
- https://attack.mitre.org/techniques/T1021/

## Source note
Original educational summary authored for CyberSentinel AI, 2026-10-07. References are guidance, not live threat feeds. Candidate mappings require analyst validation.
