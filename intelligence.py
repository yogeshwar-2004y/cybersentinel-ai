"""Transparent candidate hypotheses driven by telemetry, never synthetic labels."""

from typing import Any

# name, MITRE ID, technique name, tactic; not every application flaw has a direct ATT&CK mapping.
CATALOG = {
    "brute_force": ("Brute Force", "T1110", "Brute Force", "Credential Access"),
    "port_scan": ("Port Scanning", "T1046", "Network Service Discovery", "Discovery"),
    "exfiltration": ("Data Exfiltration", "T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),
    "dns_tunneling": ("DNS Tunneling", "T1071.004", "DNS", "Command and Control"),
    "powershell": ("PowerShell Abuse", "T1059.001", "PowerShell", "Execution"),
    "privilege_escalation": (
        "Privilege Escalation",
        "T1068",
        "Exploitation for Privilege Escalation",
        "Privilege Escalation",
    ),
    "malware": ("Malware Execution", "T1204.002", "Malicious File", "Execution"),
    "rdp": ("Suspicious RDP Activity", "T1021.001", "Remote Desktop Protocol", "Lateral Movement"),
    "ransomware": ("Ransomware Behavior", "T1486", "Data Encrypted for Impact", "Impact"),
    "phishing": ("Phishing", "T1566", "Phishing", "Initial Access"),
    "credential_dumping": ("Credential Dumping", "T1003", "OS Credential Dumping", "Credential Access"),
    "lateral_movement": ("Lateral Movement", "T1021", "Remote Services", "Lateral Movement"),
    "sql_injection": ("SQL Injection", None, None, "Initial Access"),
    "xss": ("Cross-Site Scripting", None, None, "Initial Access"),
    "command_injection": ("Command Injection", "T1059", "Command and Scripting Interpreter", "Execution"),
    "insider": ("Insider Threat", None, None, "Collection"),
}


def hypothesis(event: dict[str, Any]) -> dict:
    """Return a triage hypothesis; matching evidence does not prove exploitation."""
    text = str(event.get("message", "")).lower()
    choices = [
        ("ransomware", "file encryption burst" in text or "ransom note" in text),
        ("credential_dumping", "credential dump" in text or "lsass access" in text),
        ("powershell", "powershell" in text and ("encoded" in text or "unusual" in text)),
        ("privilege_escalation", "unexpected admin" in text or "privilege change" in text),
        ("malware", "unsigned executable" in text or "malware" in text),
        ("sql_injection", "sql syntax" in text or "sqli" in text or "union select" in text),
        ("xss", "script tag" in text or "xss" in text),
        ("command_injection", "shell metacharacter" in text or "command injection" in text),
        ("phishing", "suspicious email" in text or "phishing" in text),
        ("dns_tunneling", "dns" in text and ("long label" in text or "txt burst" in text)),
        ("port_scan", float(event.get("unique_ports", 0)) > 60),
        (
            "brute_force",
            float(event.get("failed_attempts", 0)) >= 20 or float(event.get("authentication_failures", 0)) >= 20,
        ),
        ("exfiltration", float(event.get("bytes_sent", 0)) > 150_000_000),
        ("rdp", "rdp" in text and ("new source" in text or "unusual" in text)),
        ("lateral_movement", "remote service" in text and float(event.get("destination_count", 0)) > 15),
        ("insider", "bulk export" in text and "employee" in text),
    ]
    key = next((key for key, matched in choices if matched), "unknown")
    name, technique, technique_name, tactic = CATALOG.get(key, ("Unclassified Anomaly", None, None, "Unknown"))
    critical = str(event.get("asset_criticality", "medium")).lower() in {"high", "critical"}
    risk = min(100, 45 + (25 if key != "unknown" else 0) + (15 if critical else 0) + (10 if key == "ransomware" else 0))
    severity = "Critical" if risk >= 90 else "High" if risk >= 70 else "Medium" if risk >= 40 else "Low"
    return {
        "key": key,
        "name": name,
        "technique": technique,
        "technique_name": technique_name,
        "tactic": tactic,
        "risk_score": risk,
        "severity": severity,
    }


MITIGATIONS = {
    "brute_force": [
        "Review account lockout and sign-in policy.",
        "Enable phishing-resistant MFA.",
        "Rate-limit authentication after verifying legitimate traffic.",
    ],
    "port_scan": ["Verify authorized scanner schedules.", "Restrict unnecessary services and segment exposed assets."],
    "exfiltration": [
        "Validate outbound transfer authorization and data sensitivity.",
        "After approval, restrict the suspicious egress path and preserve transfer logs.",
    ],
    "dns_tunneling": [
        "Inspect DNS query labels, answers, and resolver destinations.",
        "Require approved resolvers and investigate abnormal TXT volume.",
    ],
    "powershell": [
        "Collect process ancestry and PowerShell script block logs.",
        "Apply constrained language and application control where operationally suitable.",
    ],
    "privilege_escalation": [
        "Audit recent administrator and service account changes.",
        "Patch the suspected escalation path after root cause validation.",
    ],
    "malware": [
        "Preserve endpoint evidence and validate executable reputation.",
        "After approval, isolate affected endpoint and use trusted recovery media.",
    ],
    "rdp": [
        "Correlate RDP sessions with VPN and identity logs.",
        "Restrict remote access to approved gateways and enforce MFA.",
    ],
    "ransomware": [
        "Escalate immediately to incident command.",
        "After approval, contain affected hosts and validate offline backups before restoration.",
    ],
    "phishing": [
        "Preserve headers and attachment hashes; do not open suspicious links.",
        "Identify recipients and review related sign-ins.",
    ],
    "credential_dumping": [
        "Capture endpoint process and memory-access telemetry.",
        "After approved containment, rotate exposed credentials and invalidate sessions.",
    ],
    "lateral_movement": [
        "Correlate remote logons and service creation across hosts.",
        "Restrict east-west access and review account privileges.",
    ],
    "sql_injection": [
        "Use parameterized queries and least-privilege database accounts.",
        "Correlate WAF/application/database logs; validate whether queries executed.",
    ],
    "xss": [
        "Apply context-appropriate output encoding and safe templating.",
        "Use a restrictive Content Security Policy and investigate affected sessions.",
    ],
    "command_injection": [
        "Replace shell invocations with safe argument-based APIs.",
        "Validate inputs with allowlists and inspect application child processes.",
    ],
    "insider": [
        "Correlate data access with job role and approved business tasks.",
        "Coordinate access review with legal, HR, and security leadership.",
    ],
    "unknown": [
        "Compare activity with asset-specific historical baselines.",
        "Collect identity, network, and endpoint telemetry before containment.",
    ],
}
