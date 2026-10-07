# Scheduled Task Persistence

## Attack overview
Scheduled tasks can launch code repeatedly and survive a reboot. Most environments also rely heavily on authorized scheduled jobs.

## Indicators
New tasks with unusual paths, hidden scripts, elevated principals, or unexpected run times.

## Detection
Review task creation and change events, executable ownership, signatures, and associated change tickets.

## Mitigation
Restrict task creation privileges, audit task inventory, and remove confirmed malicious persistence after preserving evidence.

## MITRE ID
T1053.005

## References
- https://attack.mitre.org/techniques/T1053/005/

## Source note
Original educational summary authored for CyberSentinel AI, 2026-10-07. References are guidance, not live threat feeds. Candidate mappings require analyst validation.
