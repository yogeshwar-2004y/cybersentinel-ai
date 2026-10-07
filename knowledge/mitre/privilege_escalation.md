# Exploitation for Privilege Escalation

## Attack overview
A software flaw can allow execution with greater permissions. An administrative role change by itself supports a broad escalation hypothesis, not proof of exploitation of a vulnerability.

## Indicators
Unexpected privileged process tokens, exploit alerts, privilege changes outside maintenance windows, and vulnerable components.

## Detection
Correlate privilege events with process ancestry and patch inventory. Require exploit-specific evidence before confirming T1068.

## Mitigation
Patch affected components, minimize privileged execution, verify administrator changes, and investigate persistence before restoring trust.

## MITRE ID
T1068

## References
- https://attack.mitre.org/techniques/T1068/

## Source note
Original educational summary authored for CyberSentinel AI, 2026-10-07. References are guidance, not live threat feeds. Candidate mappings require analyst validation.
