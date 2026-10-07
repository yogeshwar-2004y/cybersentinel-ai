# OS Credential Dumping

## Attack overview
Attackers may obtain credential material from operating system components to support later access. Process access alerts require context about signed tools and administrative tasks.

## Indicators
Unexpected access to protected authentication processes, suspicious dump files, and subsequent privileged sign-ins.

## Detection
Correlate endpoint process ancestry, protection events, and credential use; verify which account material was accessible.

## Mitigation
Harden credential storage, limit local administrators, enable credential protection, and rotate confirmed exposed secrets after approved containment.

## MITRE ID
T1003

## References
- https://attack.mitre.org/techniques/T1003/

## Source note
Original educational summary authored for CyberSentinel AI, 2026-10-07. References are guidance, not live threat feeds. Candidate mappings require analyst validation.
