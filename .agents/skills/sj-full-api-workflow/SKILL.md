---
name: sj-full-api-workflow
description: Run and QA sj's authorized API assessment lifecycle from target recon and OpenAPI discovery through endpoint enumeration, bounded IDOR fuzzing, Bruno reproduction collections, SQLite evidence storage, and Markdown/HTML reporting. Use for sj repository tasks involving target lists, SOCKS5-routed testing, brute-to-automate chaining, numeric ID enumeration, scan regression testing, or the `run --full-workflow` command.
---

# sj Full API Workflow

Run the assessment as an evidence-preserving engineering loop: preflight, execute, inspect, fix, retest, and report. Keep active traffic inside the user's explicit authorization and target list.

## Load the runbook

Read [references/workflow.md](references/workflow.md) completely before running commands. Use its artifact names, safety gates, database checks, and resume paths.

## Establish scope

1. Confirm the repository root, authorized target file, requested proxy, database, output location, and response-capture requirement.
2. Never add hosts discovered from redirects, specifications, or response content to the allowlist unless the user authorized them.
3. Verify the SOCKS5 listener without printing credentials. Keep DNS and HTTP traffic routed through the configured proxy.
4. Refuse an existing full-workflow output directory. Preserve previous evidence instead of overwriting it.

## Verify before traffic

Build the current source and run focused tests for changed packages. For substantive changes, run the full test suite, race detector, and `golangci-lint` before starting the authorized network run.

Plan active fuzzing offline from stored automate results. Record:

- selected IDOR candidates;
- safe versus state-changing methods;
- mutation dimensions and total requests;
- the configured hard request budget; and
- deterministic requests plus the worst-case response-guided retry reserve;
- whether the complete inclusive range fits.

Do not accept silently partial range coverage.

## Execute the workflow

Prefer `sj run --full-workflow` for a new end-to-end assessment. It chains brute, automate, IDOR fuzz, Bruno collection generation, and reporting into a fresh directory. When the operator also provides an explicit identity/ownership manifest template, `--assessment-manifest` appends assessment-v2 planning, execution, and all report formats. Never infer identities, owned objects, or expected access from discovery data.

Use `--skip-brute --url-file` for known specification URLs, or `--skip-brute --brute-run` with the configured database to resume from retained brute evidence. Use `--auto-assess` when the caller needs a one-command assessment continuation without a manifest file. Automatic assessment must remain anonymous/public-control only: materialize no identities, owned objects, or ownership expectations, and never describe its results as ownership-backed authorization verification.

Use the sj MCP server's native `run_full_workflow` tool for a one-call local workflow when it is configured for the session. It accepts target URL arrays, or known specification URLs/stored brute run IDs with `skip_brute`, and defaults to automatic anonymous assessment. The server operator retains authority over the proxy, database, evidence key, allowed hosts, and artifact roots. Use individual MCP tools or the CLI only when intentionally testing a stage in isolation.

Apply these invariants:

- use the requested target-level worker count for brute only;
- keep fuzz requests sequential and paced;
- render fuzz status from immutable atomic snapshots owned by the scan goroutine; keep URLs, headers, and request/response bodies out of progress state;
- enable bounded response-guided repair and reserve every possible retry during the offline preflight;
- always exclude DELETE;
- exclude PATCH by default and require both `--allow-patch` and `--accept-risk` to send it;
- exclude POST from the full workflow by default and require both `--allow-post` and `--accept-risk` to send it;
- require a separate explicit `--accept-risk` decision for PUT and business-workflow execution;
- stop requests to the affected origin immediately on HTTP 429 or advertised depleted capacity while continuing authorized healthy origins;
- never use denial-of-service, sleep, oversized, recursive, or rate-exhaustion payloads;
- enable complete response capture for automate and fuzz; and
- keep SQLite storage enabled unless the user explicitly requests an ephemeral run.

For the optional assessment continuation:

- require persisted storage and a stable `SJ_ASSESSMENT_EVIDENCE_KEY`;
- require exactly one `kind: sj-results` input with the exact `$workflow.automate` scalar in `spec.inputs[].path` to bind the new `automate.json` artifact;
- validate and pin the complete strict template before target traffic, and require explicit identities plus owned objects;
- require every exact manifest origin to be present in the normalized `--url-file` origin set before any network stage;
- keep the manifest as the exclusive assessment transport authority and reject global proxy/SOCKS/insecure overrides;
- contain target-origin rate and verified transport failures while keeping global policy, proxy, storage, lease, and cancellation failures fatal; and
- skip assessment traffic after a global automate or fuzz failure; and
- preserve both the legacy corpus report and signed assessment-v2 reports because they cover different evidence surfaces.

## Inspect and fix

Treat a successful exit as necessary but insufficient. Independently check JSON and SQLite for:

- expected candidate and request counts;
- every numeric value in the requested range for every selected identifier dimension;
- zero DELETE requests;
- zero unexpected transport errors;
- an explicit failed run when every attempted active request has a transport error, rather than accepting an empty-looking success;
- no request-budget or rate-limit stop when claiming complete coverage;
- zero response truncation and stored body length parity; and
- matching successful run records in SQLite.

Audit real parameter names before claiming complete ID coverage. Recognize identifier suffixes and prefixes across snake case and camel case, including forms such as `account_id`, `accountId`, `IdCompany`, and `idCompany` without classifying ordinary words such as `identity` as numeric IDs.

Ensure reports count baseline automate operations separately from active fuzz probes. If per-payload probes inflate endpoint inventory, passive findings, host statistics, or OWASP candidate counts, treat that as a reporting regression.

Review differential findings structurally. Distinct hashes alone are not IDOR proof. Filter identical catch-all bodies, explicit failure envelopes, echoed identifiers, and single volatile scalar responses. Require multiple successful object-shaped responses with substantive data, then describe the result as an active-test candidate until ownership and identity boundaries are verified.

Revalidate PII heuristics against captured proof before assigning severity. In particular, do not label arbitrary 13–19 digit identifiers as payment cards; require both a recognized issuer range and a valid Luhn checksum, and still describe the result as a candidate until field context and exposure are reviewed.

Require live baseline qualification before numeric IDOR traffic for each endpoint and identity. Historical automate `2xx` status is not sufficient. Only a current 2xx, non-failure, substantive JSON object or array may release adjacent or range mutations. Record and skip 4xx/5xx, non-JSON catch-alls, explicit failure envelopes, and trivial echoed/scalar baselines. A response-guided repair of an invalid baseline is reproduction evidence, but it must be captured as a new valid operation before numeric enumeration so every mutation includes the repaired request requirements.

Review response-guided decisions as evidence, not vulnerability claims. Accept deterministic repairs for named missing fields, integer/UUID/base64 type failures, and simple enum constraints. Never execute response content, synthesize credentials or sessions, generate file uploads, or evaluate arbitrary server-provided regexes. Record credential requirements and ambiguous backend exceptions such as unnamed `NoneType` failures as unresolved hints. A repaired 2xx response proves only that the revised request was accepted; verify authorization, returned data, and side effects separately.

When a bug appears, capture it in a failing regression test, fix the smallest responsible layer, rerun local verification, rebuild, and repeat only the affected authorized network stage. Preserve superseded artifacts and identify the final run clearly.

Interrupt long runs through context-aware SIGINT/SIGTERM handling so the SQLite finalizer records `canceled`. Repair any run left stale by an older binary through the store API and document why it was canceled.

## Report and hand off

Generate both Markdown and self-contained HTML. Confirm HTML findings contain escaped, native toggleable response-proof blocks where bodies were captured, with identity, case, status, response-guided analysis, and truncation metadata.

Report completed coverage separately from protected work that was skipped. Never imply that state-changing IDOR candidates were exercised when `--accept-risk` was absent, or that distinct public objects prove broken authorization without cross-identity ownership evidence.
