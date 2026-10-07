# Network Service Discovery

## Attack overview
Service discovery enumerates reachable hosts and listening ports. Authorized vulnerability scanners and inventory systems often produce the same pattern.

## Indicators
High unique-port counts, many destinations, sequential probes, and failed connections from a single asset.

## Detection
Compare network flows with approved scanner schedules and asset inventory. Investigate unexpected internal probing and newly discovered services.

## Mitigation
Reduce exposed services, segment sensitive networks, inventory listening ports, and alert on unscheduled discovery activity.

## MITRE ID
T1046

## References
- https://attack.mitre.org/techniques/T1046/

## Source note
Original educational summary authored for CyberSentinel AI, 2026-10-07. References are guidance, not live threat feeds. Candidate mappings require analyst validation.
