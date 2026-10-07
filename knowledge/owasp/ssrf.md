# Server-Side Request Forgery

## Attack overview
A server can be tricked into requesting an unintended resource when remote request destinations are controlled by untrusted input.

## Indicators
Unexpected internal service requests, cloud metadata access, unusual URL destinations, and backend outbound connections.

## Detection
Correlate input URLs, resolved addresses, redirects, proxy records, and destination service logs. Check outbound authorization policies.

## Mitigation
Allowlist destinations, validate resolved addresses and redirects, restrict egress, and protect metadata endpoints.

## MITRE ID
No direct technique asserted. Require behavioral evidence before assigning ATT&CK.

## References
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

## Source note
Original educational summary authored for CyberSentinel AI, 2026-10-07. References are guidance, not live threat feeds. Candidate mappings require analyst validation.
