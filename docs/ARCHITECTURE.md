# Architecture and contracts

## Execution lifecycle
The dashboard scores validated telemetry with an explicitly fitted detector. Only `prediction=-1` events are accepted by Detection Agent. Intelligence retrieves relevant local chunks, Analysis produces a validated contract, Response constructs a defensive plan, and Report assembles evidence and provenance. The workflow records every stage duration and saves the final incident transactionally.

## Shared contracts
`models.Analysis` bounds severity, confidence, risk, list counts, narrative lengths, MITRE ID format, and source IDs. Unknown fields are rejected. Analysis Agent verifies each mapping against the source that claims it and verifies citations were retrieved. This prevents invented technique identifiers from silently entering a report, although plausible narrative hallucinations still require analyst review.

Each retrieval record carries `source_id`, title, path, text, technique IDs, and similarity. Source IDs have the form `relative/path.md#chunk-N`. The KB manifest stores original content, normalized vectors, and a fingerprint of content plus embedding settings. Indexes for lexical and semantic encoders never share fingerprints.

## ML boundary
Inputs are transformed with log1p. The estimator is fitted on a trusted reference and caps reference sampling at 1,024 rows per tree. Target uploads never refit the model. Re-scoring keeps event identity stable; model identity captures features, reference values, hyperparameters, and transformation version. Ground truth and event labels are excluded from inference features and threat hypothesis logic.

## Provider boundary
`LLMProvider.complete(system, prompt, json_mode)` is the stable provider API. Requests use fixed HTTPS provider endpoints or the configured Ollama endpoint, bounded timeouts, and limited retries. Redirects are not followed. Provider exceptions avoid credential-bearing payloads. JSON analysis is parsed and validated before use. Local fallback is explicit in provenance; it is a deterministic hypothesis engine, not a generative LLM.

## Persistence and concurrency
SQLite uses WAL and short-lived connections. Completed incidents are insert-only, while statuses have an audit trail and revision counter. Duplicate investigations preserve the original saved report and prior analyst decisions. Status update conflicts require a refresh. Index cache writes use unique temporary files and atomic replacement. In-process index rebuild/search is protected with a reentrant lock.

Uploads and custom estimators live in Streamlit session state. The default reference estimator and workflows are cached resources. Knowledge index, incident register, and exported reports are shared within one configured `STATE_DIR`. This is a trusted-team workspace rather than a tenant-isolated service. Reference data and runtime storage should be isolated per deployment if teams require separate access boundaries.

## Response boundary
The fixed five-agent execution order is intentionally bounded. There is no autonomous shell, endpoint, firewall, or account modification. The playbook states owner, phase, approval requirement, and validation. Approval fields are guidance rather than an execution control because the application never executes the actions.

## Provenance
A report records requested and actual provider, fallback reason, retrieval mode, KB fingerprint, detector ID, pipeline version, sources, and agent timings. Candidate attack chain stages and unknown business impact are explicitly described as unconfirmed. The model's heuristic confidence is separate from narrative analysis confidence.
