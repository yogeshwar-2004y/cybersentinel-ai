# SQL Injection

## Attack overview
Unsafe query construction can cause input to alter database query behavior. An attack string in an HTTP request does not prove successful execution.

## Indicators
SQL syntax errors, suspicious query structures, unexpected database reads, and WAF injection alerts.

## Detection
Join application, WAF, and database audit records; confirm query execution and inspect parameter binding. Do not replay payloads in production.

## Mitigation
Use prepared parameterized statements, safe query APIs, allowlists for dynamic identifiers, and least-privilege database identities.

## MITRE ID
No direct technique asserted. Require behavioral evidence before assigning ATT&CK.

## References
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

## Source note
Original educational summary authored for CyberSentinel AI, 2026-10-07. References are guidance, not live threat feeds. Candidate mappings require analyst validation.
