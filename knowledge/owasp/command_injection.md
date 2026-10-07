# OS Command Injection

## Attack overview
Untrusted input passed into a shell may change executed commands. ATT&CK interpreter mapping requires observed execution evidence rather than merely suspicious input.

## Indicators
Shell metacharacter warnings, unusual application child processes, and unexplained outbound connections.

## Detection
Correlate request logs with process ancestry and execution audit records; review how application code invokes operating system utilities.

## Mitigation
Avoid shell invocation, use argument-based APIs, validate against strict allowlists, and minimize service privileges.

## MITRE ID
T1059

## References
- https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- https://attack.mitre.org/techniques/T1059/

## Source note
Original educational summary authored for CyberSentinel AI, 2026-10-07. References are guidance, not live threat feeds. Candidate mappings require analyst validation.
