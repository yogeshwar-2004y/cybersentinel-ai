# Data from Local System

## Attack overview
An actor may collect information from files and local storage before transferring it. Backup and indexing applications also read large data volumes.

## Indicators
Bulk reads of sensitive paths, archive creation, unauthorized access, and staging files.

## Detection
Correlate file access, process identity, data classification, approved backups, and subsequent outbound transfers.

## Mitigation
Apply least-privilege file access, monitor sensitive repositories, and limit unnecessary local copies of regulated data.

## MITRE ID
T1005

## References
- https://attack.mitre.org/techniques/T1005/

## Source note
Original educational summary authored for CyberSentinel AI, 2026-10-07. References are guidance, not live threat feeds. Candidate mappings require analyst validation.
