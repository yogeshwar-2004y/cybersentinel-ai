"""Reproducible synthetic five-minute security windows; not real production telemetry."""

from pathlib import Path
from datetime import datetime, timedelta, timezone
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
FEATURES = [
    "failed_attempts",
    "login_frequency",
    "bytes_sent",
    "bytes_received",
    "request_rate",
    "unique_ports",
    "authentication_failures",
    "destination_count",
]
ATTACKS = {
    "Brute Force": (
        {0: (40, 180), 1: (60, 220), 6: (40, 180)},
        "Repeated authentication failures followed by a success",
    ),
    "Malware": (
        {2: (10000000, 45000000), 4: (200, 450), 7: (20, 45)},
        "Unsigned executable with unusual outbound connections",
    ),
    "SQL Injection": ({4: (350, 850), 3: (9000000, 30000000)}, "WAF SQL syntax anomaly and SQLi pattern in request"),
    "PowerShell Abuse": (
        {2: (8000000, 40000000), 4: (150, 400)},
        "Unusual PowerShell encoded invocation with child process",
    ),
    "RDP Login": ({1: (50, 100), 7: (18, 35), 6: (20, 50)}, "RDP login from new source with unusual target fan-out"),
    "Privilege Escalation": (
        {1: (50, 120), 4: (250, 650)},
        "Unexpected admin privilege change with new privileged session",
    ),
    "DNS Tunneling": (
        {4: (700, 1800), 2: (10000000, 45000000), 7: (20, 50)},
        "DNS long label and TXT burst to unfamiliar resolver",
    ),
    "Port Scan": (
        {5: (120, 700), 7: (50, 180), 4: (400, 1400)},
        "Connection attempts across many ports and destinations",
    ),
    "Data Exfiltration": ({2: (250000000, 1400000000), 7: (15, 40)}, "Large outbound transfer to external destination"),
    "Ransomware": ({4: (450, 900), 2: (20000000, 60000000)}, "File encryption burst and ransom note indicator"),
    "Phishing": ({1: (60, 120), 6: (25, 70)}, "Suspicious email followed by anomalous sign-in activity"),
    "XSS": ({4: (400, 850), 3: (8000000, 22000000)}, "WAF script tag and XSS pattern in request"),
    "Command Injection": (
        {4: (350, 850), 2: (10000000, 35000000)},
        "Application shell metacharacter warning and unexpected child process",
    ),
    "Insider Threat": (
        {2: (80000000, 140000000), 4: (300, 600)},
        "Employee bulk export outside approved work schedule",
    ),
    "Credential Access": (
        {1: (55, 140), 7: (20, 50)},
        "LSASS access credential dump alert with unusual process lineage",
    ),
}


def row(rng: np.random.Generator, index: int, label: str, base: datetime) -> dict:
    values = [
        int(rng.poisson(0.6)),
        int(rng.integers(1, 12)),
        int(rng.lognormal(12.4, 0.6)),
        int(rng.lognormal(13.6, 0.65)),
        int(rng.integers(5, 90)),
        int(rng.integers(1, 8)),
        int(rng.poisson(0.8)),
        int(rng.integers(1, 9)),
    ]
    message = "Authorized interactive login and ordinary service traffic"
    if label == "Failed Login":
        values[0] = int(rng.integers(2, 8))
        values[6] = values[0]
        message = "Occasional incorrect password; subsequent normal activity"
    if label in ATTACKS:
        overrides, message = ATTACKS[label]
        for feature, (low, high) in overrides.items():
            values[feature] = int(rng.integers(low, high))
    return {
        "timestamp": (base + timedelta(minutes=5 * index)).isoformat(),
        "source_ip": f"10.20.{index % 12}.{index % 240 + 10}",
        "destination_ip": f"10.40.{index % 8}.{index % 240 + 10}" if index % 4 else f"198.51.100.{index % 200 + 1}",
        "user": f"analyst_{index % 40:02d}",
        "host": f"endpoint-{index % 70:03d}",
        "event_type": label,
        "message": message,
        "asset_criticality": "high" if index % 5 == 0 else "medium",
        **dict(zip(FEATURES, values)),
        "ground_truth": "anomaly" if label in ATTACKS else "normal",
    }


def generate() -> None:
    base = datetime(2026, 9, 1, tzinfo=timezone.utc)
    rng = np.random.default_rng(42)
    labels = ["Normal Login"] * 700 + ["Failed Login"] * 75 + [k for k in ATTACKS for _ in range(15)]
    rng.shuffle(labels)
    data = pd.DataFrame([row(rng, i, label, base) for i, label in enumerate(labels)])
    reference_rng = np.random.default_rng(1007)
    reference = pd.DataFrame(
        [
            row(reference_rng, i, "Failed Login" if i % 10 == 0 else "Normal Login", base - timedelta(days=10))
            for i in range(800)
        ]
    )
    (ROOT / "data").mkdir(exist_ok=True)
    data.to_csv(ROOT / "data/security_logs.csv", index=False)
    reference.to_csv(ROOT / "data/baseline_logs.csv", index=False)
    print(f"Generated {len(data)} demo rows and {len(reference)} independent baseline rows.")


if __name__ == "__main__":
    generate()
