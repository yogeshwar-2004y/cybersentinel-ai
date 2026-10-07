# Synthetic telemetry
`security_logs.csv`: 1,000 independent evaluation/demo windows, including 225 anomalous windows and 775 normal windows.
`baseline_logs.csv`: 800 independently generated normal windows with a separate random seed.
No real personal data or active malicious payloads are included. Private/documentation IP ranges are used.

All rows describe a five-minute host/user telemetry window. The detector uses only the eight columns below.

| Feature | Definition |
|---|---|
| failed_attempts | Failed login attempts in the window |
| login_frequency | Total authentication events in the window |
| bytes_sent | Total outbound bytes |
| bytes_received | Total inbound bytes |
| request_rate | Mean requests per minute in the window |
| unique_ports | Distinct destination ports |
| authentication_failures | Failed authentication operations across services |
| destination_count | Distinct destinations |

`ground_truth` is solely for synthetic evaluation. `event_type` is informational and is not used to identify threats or train the model.
`message` provides qualitative telemetry used in candidate triage. Synthetic thresholds are demonstrative and require tuning on your own environment.

Recreate both CSV files: `python scripts/generate_data.py`.
