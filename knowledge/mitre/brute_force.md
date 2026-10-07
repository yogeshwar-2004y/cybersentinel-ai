# Brute Force

## Attack overview
Repeated guessing or reuse of credentials can create bursts of unsuccessful authentication. A successful sign-in after failures increases investigative priority but does not prove account takeover.

## Indicators
High failed-attempt counts, multiple targeted accounts, new source networks, and sign-in success after failure bursts.

## Detection
Aggregate identity events by source and account; compare with ordinary retry behavior and check distributed attempts. Validate timestamps and distinguish service misconfiguration from deliberate guessing.

## Mitigation
Use MFA, password hygiene, measured rate limits, and lockout policies that avoid easy denial of service. Review exposed accounts and preserve authentication records.

## MITRE ID
T1110

## References
- https://attack.mitre.org/techniques/T1110/

## Source note
Original educational summary authored for CyberSentinel AI, 2026-10-07. References are guidance, not live threat feeds. Candidate mappings require analyst validation.
