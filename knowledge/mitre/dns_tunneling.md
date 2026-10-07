# DNS Tunneling

## Attack overview
DNS may be used to carry command-and-control messages hidden among normal lookups. Certain DNS behavior may also support data transfer, which requires separate evidence.

## Indicators
Long high-entropy labels, repeated TXT queries, unfamiliar domains, and unusual resolver traffic.

## Detection
Compare query lengths, label diversity, response types, and domain frequency with asset baselines. Inspect relevant packet samples under approved procedures.

## Mitigation
Require approved recursive resolvers, monitor unusual query patterns, and investigate suspicious domains before blocking business-critical traffic.

## MITRE ID
T1071.004

## References
- https://attack.mitre.org/techniques/T1071/004/

## Source note
Original educational summary authored for CyberSentinel AI, 2026-10-07. References are guidance, not live threat feeds. Candidate mappings require analyst validation.
