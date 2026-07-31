---
name: sj-findings-analysis
description: Thoroughly validate sj API security findings against retained request and response evidence. Use when reviewing targets results, legacy sj SQLite runs, fuzz JSON/JSONL, assessment-v2 databases, logs, generated reports, or suspected IDOR/BOLA/BFLA, persistent writes, PII, credentials, verbose backend errors, injection, mass assignment, authentication, rate-limit, shadow API, WebSocket, or other API vulnerability signals.
---

# SJ Findings Analysis

Analyze retained sj evidence offline before proposing more traffic. Build proof chains, independently hunt for missed findings, collapse repeated probes, and suppress unsupported findings before report limits.

Read [analysis-oracles.md](references/analysis-oracles.md) completely before classifying findings.

## Safety and Evidence Invariants

- Do not send traffic unless the user explicitly authorizes another active test. Preserve the authorized scope, proxy, budgets, and destructive safeguards.
- Never replay POST, PUT, PATCH, or DELETE merely to improve a report.
- Do not invent missing headers, identities, timestamps, ownership, or authentication. Use `unknown` and reduce confidence.
- Keep credential-bearing headers out of reports. Full evidence means every retained safe field, not reconstructed secrets.
- Do not copy matched PII or credentials into chat, shell output, tickets, titles, or summaries. Report types and locations; show originals only in the secured evidence view.
- Fail closed on truncated, tampered, undecryptable, or provenance-ambiguous proof.

## Workflow

### 1. Inventory and Establish Trust Order

Enumerate every requested result file, database, log, and report. Identify legacy runs/observations/findings; assessment-v2 attempts/comparisons/artifacts/lineage/seals; brute, automate, fuzz, guided, workflow, and Bruno outputs.

Use this trust order: integrity-verified raw exchanges; raw database observations; raw JSON/JSONL probes; stored finding summaries; generated Markdown/HTML. For a fresh analysis, exclude prior reports and analyst conclusions until independent classification is complete.

Do not start from stored high/medium findings. Independently sweep every retained response body for disclosure and sensitive-data families, and every ordered POST/PUT/PATCH plus later GET sequence for stable-marker readback. Stored findings are hypotheses and regression inputs—not the corpus index.

Prefer a private SQLite snapshot created with the SQLite backup API from a read-only connection; this incorporates committed WAL content without copying a live database and sidecars at different instants. Hash the snapshot and analyze it with `mode=ro` plus `query_only`. If snapshotting is unavailable, use one read transaction, hash the database plus WAL/SHM before and after, and fail closed if they change. Use bounded, redaction-first queries; avoid printing raw bodies in tool output.

### 2. Normalize Without Losing Occurrences

Normalize by origin, method, path template, query keys, status, identity, auth context, semantic digest, run ID, observation ID, and time. Retain each occurrence for sequence analysis even when two exchanges have identical content and inventory views deduplicate endpoints. When timestamps tie, order by the database observation ID or file-array index and label the fallback.

Group enumeration values under one endpoint template. Deduplicate canceled/completed retries by origin, method, template, digest, disclosure family, and time window; preserve the strongest complete run and record duplicate counts separately. Correlate guided JSON to a stored run only through an embedded ID; otherwise label timestamp/count/digest correlation as inferred.

### 3. Hunt Every API Vulnerability Class

Evaluate BOLA/IDOR, BFLA, persistent writes, BOPLA/excessive data, mass assignment, authentication/tokens/API keys, PII/financial/health/internal metadata, verbose errors, injection, SSRF, redirects, file/path handling, business flows, replay/races/idempotency, rate/resource abuse, shadow/zombie/versioned APIs, gateway differences, GraphQL, WebSockets, and mobile backends.

Use the reference proof oracles. A route name, status code, numeric identifier, size/hash difference, or generic error is inventory—not a vulnerability.

### 4. Apply False-Positive Controls Before Limits

Suppress explicit failure envelopes, generic errors, catch-all responses, echoes, trivial scalars, volatile-only differences, public catalogs/config, reserved scanner data, invalid issuer/Luhn card candidates, same-identity enumeration, and `disproved` controls. A single generic scanner marker such as `testvalue` is weak: require an identifier-key match, a second stable field, or a non-generic unique marker.

For BOLA, require distinct authorized identities, known victim ownership, a substantive victim baseline, attacker replay of the victim object, expected denial, and a negative control.

Treat a bare `NoneType`, `HttpRequestException`, localized exception label, product name, ordinary Pydantic validation detail, or generic upstream-client exception as lower specificity. Keep these out of medium/high findings unless another independent family or concrete internal target is present; a bounded low-severity implementation-disclosure finding may be appropriate when schema names, internal hosts, or dependency details are actually exposed. Treat pyodbc/ODBC exception classes, SQL/parameters, SQLAlchemy diagnostics, stack traces, absolute source paths with line numbers, and database objects/constraints/procedures as high-specificity disclosure families.

Run suppression and deduplication before finding/evidence limits. Never render false-positive controls as findings.

### 5. Assemble Complete Proof Chains

Retain ordered roles: baseline, mutation, immediate readback, update, later readback, victim control, attacker replay, expected denial, negative control, and rollback. Include method, URL, retained safe headers, request body, response status, retained safe headers, response body, truncation, identity/auth context, run/observation IDs, and time. Explicitly report missing rollback evidence and possible residual test data; never replay a mutation solely to clean it up without renewed authorization.

Bound repetition while keeping one complete exchange per endpoint family and each distinct control role.

### 6. Classify Honestly

- `confirmed`: required exploit and negative controls prove the boundary failure.
- `tested`: concrete side effect/disclosure exists, but a policy, auth, or ownership fact is unknown.
- `candidate`: meaningful evidence warrants a focused authorized reproduction.
- `disproved`: controls explain the signal or the boundary held.
- `coverage gap`: evidence/identity/workflow was missing, truncated, or transport-limited.

Missing auth context changes `anonymous` to `unknown`; missing ownership prevents BOLA confirmation; missing headers reduces completeness but not body-backed disclosure; truncated proof cannot confirm semantic readback; inferred run correlation cannot raise a candidate to confirmed.

Do not label SQL disclosure as SQL injection, public data as IDOR, an upstream exception as SSRF, or a persistent write as unauthenticated when auth was not retained.

### 7. Verify the Report

When a generated report is in scope, confirm actionable findings sort highest severity first, repetitions collapse, false positives are absent, and highlighted findings link to full retained request/response proof. Verify dark/light mode, search, pagination, severity sorting, and safe HTML escaping. If the captured source itself returned the literal `REDACTED`, preserve it and label it as source-supplied; sj must never replace retained evidence with its own placeholder. Credential headers remain omitted.

Treat generated Bruno collections as reproduction metadata unless they contain retained responses; do not substitute a request-only collection for response evidence.

End with severity-ordered confirmed/tested findings, candidates, disproved classes, and coverage gaps; give exact local evidence references and the safest next test.
