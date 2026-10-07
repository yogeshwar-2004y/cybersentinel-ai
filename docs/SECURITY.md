# Security boundaries

This application provides decision support to a trusted SOC workspace. It is runnable and tested, but deploying it with real telemetry requires controls appropriate to the organization.

## Input handling
CSV inputs require eight finite non-negative features and valid optional timestamps. Maximum intake is 20 MiB and 50,000 rows. Text fields are bounded. Uploaded filenames are display-only and are not used as filesystem paths. User/provider text is not inserted into trusted HTML, evaluated as code, or interpreted as shell commands. PDF markup is escaped. Markdown escapes markup syntax and HTML characters. Source knowledge excerpts are displayed as plain text.

## LLM handling
Event and context content are treated as untrusted data in prompts. Structured responses are validated with Pydantic and citations/techniques are checked against retrieved source records. This reduces, but cannot eliminate, hallucination or prompt injection. Hosted transmission is disabled by default. Redaction omits identifiers and masks common credentials, IPv4 addresses, and emails, but cannot identify every form of sensitive data. Custom KB content and chat history may contain sensitive information; review them before cloud use.

Never use provider output as executable instructions without a separate authorized response system. Disruptive playbook steps are recommendations with named owners and approval expectations.

## Persistence
No pickle or joblib artifacts are loaded. Cached vectors use NumPy `allow_pickle=False`. Incident queries use SQL parameters; status mutation is transactionally audited. The main database file is given restrictive permissions when supported, but WAL files and folder access depend on platform and deployment permissions. Evidence and chat/export data are not application-layer encrypted. Use filesystem encryption, restricted directories, backups, and retention policy where required.

## Access
Local launch binds to 127.0.0.1. `REQUIRE_AUTH=true` enables a native Streamlit OIDC sign-in gate when properly configured. Authentication does not provide role authorization. All authenticated users in one deployment share the incident workspace. Enforce the allowed analyst group at your identity provider or gateway. There is no multi-tenant isolation or per-user incident access policy in this version.

The audit trail records status transitions and an analyst-provided note; it does not cryptographically verify authorship or provide tamper-proof audit retention. Export these records to an approved audit system if stronger guarantees are required.

## Recommended operational controls
Use TLS and SSO, approved access groups, least-privilege runtime credentials, secrets outside source control, protected runtime storage, encrypted backups, reviewed retention, and network egress restrictions. Treat embedding model caches and knowledge documents as trusted deployment artifacts; remote model code is disabled.

## Limitations
Aggregate-feature anomaly detection is not a signature engine and cannot detect every attack. Qualitative messages improve triage only for events the model flagged. Threat mappings are candidates; T1068 requires exploit evidence, T1048 requires protocol evidence, and T1204.002 requires user execution evidence. SQL injection and XSS are not assigned invented direct ATT&CK IDs. Risk and confidence are heuristic and require analyst validation.

Any real incident response action should follow your organization's authority, legal obligations, evidence-handling requirements, and service continuity procedures.
