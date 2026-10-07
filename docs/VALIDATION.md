# Verification record

Build verified on 2026-10-07 with Python 3.12.14.

## Executed checks

- `python -m pytest -q`: **54 passed**.
- `python -m ruff check .`: passed.
- `python -m compileall -q .`: passed.
- Local CLI workflow: CSV scoring, five agents, SQLite persistence, Markdown/JSON/PDF generation.
- Real Sentence Transformer (`sentence-transformers/all-MiniLM-L6-v2`) + FAISS retrieval, complete local incident workflow, grounded T1110 mapping.
- Streamlit AppTest: all five real pages populated with an incident; main navigation; Dashboard investigation button; unauthenticated OIDC gate fails closed.
- Mocked OpenAI, Gemini, and Ollama transport contracts, cloud opt-in behavior, invalid provider output, redaction, and strict fallback behavior.
- Corrupt/malformed input rejection, label exclusion, stable event identity when re-scoring, immutable report deduplication, status audit, and revision conflicts.
- Parseable JSON/PDF, required report sections, untrusted HTML escaping, and four-page sample PDF rendered and visually reviewed.

## Synthetic benchmark

These metrics describe the bundled synthetic dataset only. They are not production accuracy estimates.

| Reference | Reference rows used | Target rows | Alerts | Attack precision | Attack recall | Attack F1 |
|---|---:|---:|---:|---:|---:|---:|
| Dashboard independent baseline | 800 | 1,000 | 225 | 69.33% | 69.33% | 69.33% |
| Trainer baseline subset | 640 | 1,000 | 217 | 64.52% | 62.22% | 63.35% |

The target contains 775 normal and 225 anomalous windows. Dashboard confusion matrix:

| Actual / predicted | Normal | Anomaly |
|---|---:|---:|
| Normal | 706 | 69 |
| Anomaly | 69 | 156 |

The eight aggregate features miss some synthetic attacks and generate some false alarms. Validation on an organization's held-out data and representative normal reference is required before relying on the model for SOC prioritization. Calibration and host-specific baselines remain future work.

## Tested dependency versions

| Dependency | Version |
|---|---|
| Streamlit | 1.65.0 |
| NumPy | 2.3.5 |
| Pandas | 2.2.3 |
| Scikit-learn | 1.8.0 |
| FAISS CPU | 1.15.1 |
| Plotly | 7.1.0 |
| Sentence Transformers | 6.1.0 |
| Pydantic | 2.13.5 |
| Requests | 2.34.2 |
| python-dotenv | 1.2.4 |
| ReportLab | 4.4.9 |
| Pillow | 12.3.0 |
| pytest | 9.1.1 |
| pypdf | 6.10.0 |
| Ruff | 0.16.10 |

## Verification limits

Live billable hosted-provider requests were not made; provider behavior was verified with transport mocks. Live Ollama generation, a real OIDC login, and container builds were not executed. GUI pages were exercised with Streamlit AppTest; browser screenshots and an externally reachable HTTP endpoint were unavailable in this environment. Model weights were downloaded for semantic integration testing and are not part of the ZIP.

Optional native OIDC provides a sign-in gate, not per-user authorization or tenant isolation. All admitted analysts in a deployment share its configured incident history. Deployment requirements and remaining boundaries are described in SECURITY.md and DEPLOYMENT.md.
