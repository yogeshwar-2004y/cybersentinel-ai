# Broken Access Control

## Attack overview
Authorization flaws may allow a user to read or modify resources outside permitted scope. Authentication success is separate from authorization correctness.

## Indicators
Cross-account resource access, unexpected administrative actions, and ownership mismatches.

## Detection
Compare user identity, requested object, tenant boundary, and server-side policy decisions. Verify using approved test accounts.

## Mitigation
Enforce server-side authorization for every action, deny by default, and test role and tenant boundaries.

## MITRE ID
No direct technique asserted. Require behavioral evidence before assigning ATT&CK.

## References
- https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

## Source note
Original educational summary authored for CyberSentinel AI, 2026-10-07. References are guidance, not live threat feeds. Candidate mappings require analyst validation.
