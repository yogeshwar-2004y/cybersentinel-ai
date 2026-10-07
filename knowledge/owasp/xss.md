# Cross-Site Scripting

## Attack overview
Untrusted content can execute in a browser when a page renders it in an unsafe context. Reflection of a string does not establish browser execution.

## Indicators
Suspicious script-shaped input, unsafe rendering sinks, unexpected browser callbacks, and session anomalies.

## Detection
Review input source, output context, templating behavior, and browser evidence. Distinguish stored, reflected, and DOM-based paths.

## Mitigation
Apply context-specific output encoding, safe templating, vetted sanitization for allowed HTML, and a restrictive Content Security Policy.

## MITRE ID
No direct technique asserted. Require behavioral evidence before assigning ATT&CK.

## References
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

## Source note
Original educational summary authored for CyberSentinel AI, 2026-10-07. References are guidance, not live threat feeds. Candidate mappings require analyst validation.
