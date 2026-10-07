# Security Logging and Monitoring

## Attack overview
Consistent security telemetry makes incident reconstruction possible. Missing context can hide both malicious activity and ordinary operational explanations.

## Indicators
Collector gaps, absent correlation identifiers, inconsistent clocks, and unaudited privileged actions.

## Detection
Review telemetry coverage, parse failures, time synchronization, retention, and alert routing. Verify event delivery end to end.

## Mitigation
Centralize structured logs, protect log integrity, exclude secrets, define retention, and test alert escalation procedures.

## MITRE ID
No direct technique asserted. Require behavioral evidence before assigning ATT&CK.

## References
- https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

## Source note
Original educational summary authored for CyberSentinel AI, 2026-10-07. References are guidance, not live threat feeds. Candidate mappings require analyst validation.
