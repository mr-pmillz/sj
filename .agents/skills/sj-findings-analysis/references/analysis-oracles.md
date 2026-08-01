# API Finding Proof Oracles

Use these minimum oracles before promoting a signal. They are additive: application-specific policy may require more evidence.

## Authorization

### BOLA / IDOR

Require two distinct authorized identities, known ownership of the object by the victim identity, a substantive victim baseline, an attacker replay that returns the victim object, an expected-denial control, and a negative control using a nonexistent or unrelated identifier. Reject failure envelopes, public objects, trivial bodies, catch-all equivalence, echoes, and volatile-only differences.

### BFLA

Require a function with a known role restriction and a lower-privileged or anonymous identity that completes the protected action. A successful status without policy evidence or side-effect verification is only a candidate.

### Persistent Modification

Require a successful POST/PUT/PATCH, a substantive non-failure response, a stable submitted marker or object identifier, and a later successful read returning matching object content. A generic scanner value such as `testvalue` needs an identifier-key match, a second matching stable field, or a non-generic unique companion value. A later run or meaningful time interval increases persistence confidence. Truncated evidence cannot confirm semantic readback. If auth context is unknown, describe the finding as a persistent modification with unrecorded authentication context—not unauthenticated access. State whether rollback was observed and whether residual test data may remain.

## Data Exposure

### PII and Credentials

Detect structured values with field context. Payment cards require recognized issuer syntax and a valid Luhn checksum. Ignore reserved scanner emails, public role mailboxes, schema/property names, detector catalogs, examples, and long numeric identifiers without context. Report types and JSON pointers outside the secured evidence view, never matched values. Suppress intended token issuance only for a successful POST to an actual issuance endpoint whose parsed response contains an expected credential field; an auth-adjacent route name alone is never sufficient. Browser-delivered API keys are candidates until validity, origin/application restrictions, enabled APIs, quota, and billing impact are verified; presence alone is not a confirmed credential leak.

### Excessive Data / BOPLA

Require a field that the tested identity should not receive, supported by role/schema/policy evidence or a differential response. A large response alone is not excessive exposure.

## Error and Injection Signals

### Verbose Backend Disclosure

One high-specificity signal or two independent lower-specificity families are sufficient for a medium backend-disclosure finding. High-specificity examples include stack traces, absolute source paths with line numbers, pyodbc/JDBC/Npgsql/psycopg exception names, SQLAlchemy diagnostic text, `[SQL: ...]`, `[parameters: ...]`, stored-procedure invocations, and database/schema/table/column/constraint names in an exception. Lower-specificity signals include a bare `NoneType`, `HttpRequestException`, generic framework exception, database product name, ordinary Pydantic validation diagnostics, or a generic upstream-client exception. Pydantic schema/field details and urllib3 resolution failures that expose internal hosts or paths may be reported as bounded low-severity implementation disclosures, but must not be promoted to medium merely because the response is a 4xx/5xx. Generic errors and localized messages without implementation details are not findings. Group repetitions by origin, method, templated path, and disclosure family.

### Injection

Error disclosure does not prove injection. Require a controlled payload-dependent semantic effect, time/control comparison, out-of-band callback, or other vulnerability-specific oracle. Use paired negative controls and reject unstable downstream failures.

## Network and Workflow Abuse

### SSRF

Require a controlled callback or a reliable paired internal/external destination oracle. A parameter named URL, webhook, callback, import, or fetch is only inventory.

### Rate Limit / Resource Consumption

Require a bounded, authorized test demonstrating absent or bypassable enforcement relative to documented policy. Do not exhaust resources. Route names such as bulk, export, or search do not prove abuse.

### Business Logic / Replay / Race

Require a documented state-machine invariant and an observed violation, such as duplicate value transfer, skipped prerequisite, replayed one-time action, or concurrency-dependent double commit. Status codes alone are insufficient.

## Evidence Completeness

A complete exchange contains the retained method, URL, safe headers, request body, response status, safe headers, response body, truncation flags, identity/auth context, provenance, and time. Historical evidence may lack some fields; disclose that limitation and reduce confidence rather than reconstructing data.

Never treat a cryptographic response hash, finding summary, or rendered HTML row as a substitute for the underlying request and response when those are available.
