# PowerShell Abuse

## Attack overview
PowerShell is a legitimate administration engine that can also execute attacker-controlled instructions. Encoding is an investigative clue rather than proof of malware.

## Indicators
Encoded command arguments, unusual parent processes, unexpected network connections, and disabled script logging.

## Detection
Join script-block, module, process-creation, and network logs. Identify the administrator or automation job responsible for execution.

## Mitigation
Centralize script logging, use application control, least privilege, and constrained language where supported. Preserve script content for authorized forensic review.

## MITRE ID
T1059.001

## References
- https://attack.mitre.org/techniques/T1059/001/

## Source note
Original educational summary authored for CyberSentinel AI, 2026-10-07. References are guidance, not live threat feeds. Candidate mappings require analyst validation.
