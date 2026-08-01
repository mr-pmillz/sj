# sj full API workflow runbook

## Default artifacts

Use a fresh base such as `targets/results/<assessment-name>/`. The full workflow writes:

- `brute.json`, `brute.jsonl`, `brute.csv`, and `brute.txt`;
- `automate.json`, `automate.jsonl`, and `automate.csv`;
- `fuzz.json`;
- `bruno/`;
- `report.md` and `report.html`; and
- immutable command runs in the selected SQLite database.

With `--assessment-manifest`, the same directory also contains `assessment.db`, the materialized manifest, plan/run JSON, JSON/Markdown/HTML/SARIF/JUnit reports, and a Bruno reproduction ZIP. Legacy and assessment-v2 reports are both required because they analyze different evidence models.

Keep captured target data out of commits.

## End-to-end command

```bash
./bin/sj \
  --socks5-proxy socks5://127.0.0.1:9000 \
  --database targets/results/authorized-qa.db \
  --max-response-bytes 1073741824 \
  -o targets/results/full-workflow \
  run --full-workflow \
  --url-file targets/unique-base-urls.txt \
  --workers 20 \
  --exclude DELETE \
  --idor-range 1-100 \
  --max-cases 4096 \
  --max-fuzz-requests 20000 \
  --delay 500ms \
  --max-evidence 100
```

DELETE remains excluded. PATCH and POST remain excluded from the full workflow unless the operator supplies `--allow-patch` or `--allow-post`, respectively, together with `--accept-risk`, after separately authorizing those requests and confirming suitable test data and cleanup semantics.

To append ownership-backed assessment-v2, use a normal strict assessment manifest with exactly one `kind: sj-results` input whose path is the exact scalar `$workflow.automate`, then add `--assessment-manifest /absolute/path/to/template.yaml`. The workflow reads the template once, validates it before target traffic against a private synthetic input, requires explicit identity and ownership facts, requires every manifest origin in the normalized `--url-file` origin set, pins it, and binds that scalar to its own `automate.json`; zero, duplicate, wrong-kind, or out-of-scope-origin bindings fail closed, and no other values are interpolated. It never invents identity/ownership declarations. Keep `SJ_ASSESSMENT_EVIDENCE_KEY` stable, do not use `--no-database`, and declare assessment proxy/TLS policy in the manifest rather than global transport flags.

For a one-command anonymous continuation, add `--auto-assess`. sj generates and pins the strict manifest internally from the authorized origins, current automate artifact, configured transport, safe budgets, and evidence policy. It creates no identities or owned objects and therefore does not claim cross-identity or ownership-backed coverage. With known specifications, add `--skip-brute --url-file`; to resume discovery evidence from SQLite, add `--skip-brute --brute-run RUN_ID` with the global `--database` path.

For local MCP automation, call `run_full_workflow` once with `targets`, or with `skip_brute=true` and either `spec_urls` or `brute_run_ids`. Automatic anonymous assessment is the default. Supply a new absolute `output_directory` beneath an operator-configured assessment root; the MCP server supplies and confines the database, proxy, evidence key, host allowlist, and artifact root. Do not pass captured target data through the MCP response—the tool returns artifact names and lifecycle identifiers.

For mass target sets, treat 429, advertised depleted capacity, and repeated proven target-origin transport failures as per-origin circuit breakers in brute, automate, and fuzz. A direct transport is target-attributable; a SOCKS transport requires a target-specific reply, while ambiguous proxy failures remain global. Assessment-v2 also isolates rate stops, conservative direct DNS/connection-refused failures, and target failures that a required healthy proxy can prove are origin-local. Preserve workflow-wide failures for invalid policy/configuration, cancellation, shared or unverified transport failure, request-budget exhaustion, and evidence output/database failures. The combined workflow may return success for a typed partial assessment only after the sealed run result and every requested report are durable.

The 1 GiB value is sj's emergency read ceiling, not permission to consume unbounded service resources. Validate `response_truncated=false` for every final automate and fuzz observation.

## Stage resume commands

If an earlier run already produced evidence, resume without repeating broad recon.

### Numeric read-only IDOR fuzz

```bash
./bin/sj \
  --socks5-proxy socks5://127.0.0.1:9000 \
  --database targets/results/authorized-qa.db \
  --max-response-bytes 1073741824 \
  -o targets/results/idor-1-100.json \
  fuzz \
  --run AUTOMATE_RUN_ID \
  --scope idor \
  --idor-range 1-100 \
  --max-cases 4096 \
  --max-requests 20000 \
  --response-guided \
  --max-guided-retries 2 \
  --progress \
  --delay 500ms \
  --store-responses \
  --max-stored-response-bytes 1073741824 \
  --output-format json \
  --color always
```

Supply every automate run needed for complete coverage with repeated `--run`. Without `--accept-risk`, sj records state-changing candidates as skipped and sends only read-oriented requests.

### Bruno collection

```bash
./bin/sj --database targets/results/authorized-qa.db \
  -o targets/results/bruno \
  collection --run AUTOMATE_RUN_ID --scope all
```

### Report with proof

```bash
./bin/sj --database targets/results/authorized-qa.db \
  -o targets/results/report \
  report \
  --run BRUTE_RUN_ID \
  --run AUTOMATE_RUN_ID \
  --run FUZZ_RUN_ID \
  --output-all-formats \
  --max-evidence 100 \
  --color always
```

## Verification queries

Use `jq` to inspect summaries without printing bodies:

```bash
jq '{summary, findings: [.findings[] | {severity,category,title,method,url,evidence}]}' fuzz.json
jq '{guided_retries:.summary.guided_retries, guided_successes:.summary.guided_successes, unresolved_hints:.summary.unresolved_hints, guided_probes:([.probes[]|select(.category=="response_guided")]|length)}' fuzz.json
jq '{qualified:.summary.qualified_idor_baselines, rejected:.summary.rejected_idor_baselines, skipped_invalid:.summary.skipped_invalid_idor}' fuzz.json
jq '[.probes[] | select(.category=="idor_range")] | group_by(.baseline_url) | map({url:.[0].baseline_url, cases:length, unique_cases:(map(.case)|unique|length), statuses:(map(.status)|unique)})' fuzz.json
jq '{delete_requests:([.probes[]|select(.method=="DELETE")]|length), truncated:([.probes[]|select(.response_truncated==true)]|length), transport_errors:([.probes[]|select((.error//"")!="")]|length)}' fuzz.json
```

Use `sj runs --json` and read-only SQLite queries to confirm the final run status, observation count, total stored response bytes, and `response_truncated=0`. Compare byte lengths in SQLite rather than `jq` string lengths because JSON text can contain multibyte Unicode.

When progress is enabled, verify it is rendered on stderr from immutable atomic snapshots. Progress may contain aggregate counts plus a terminal-safe method/case label, but never URLs, identity headers, request bodies, or response bodies. Treat an all-transport-error active run as failed even when its diagnostic observations were preserved.

Inspect actual path, query, and JSON-body field names before active traffic. Include suffix and prefix ID conventions (`*_id`, `accountId`, `IdCompany`, `idCompany`) in the offline plan, and reject a mutation ceiling that cannot cover every selected dimension.

Verify that every numeric series was released by a live baseline for the same identity. The qualifying response must be current 2xx substantive JSON data, not merely a historical automate success, catch-all body, explicit application failure, or echoed scalar. Treat rejected baselines and their skipped IDOR cases as false-positive prevention and an explicit coverage gap.

The preflight request count must include baseline and mutation probes plus the worst-case response-guided reserve. Review every `guidance` value without printing response bodies. Structured validation repairs may proceed within the budget; do not invent authentication material, upload files, or guess unnamed backend requirements. Treat `response_guided_success` as a reproduction lead rather than a vulnerability until data access, authorization, or a persisted side effect is independently verified.

Revalidate PII types using captured bodies without printing matched values. Payment-card candidates must pass a recognized issuer-range check and Luhn checksum; long IDs that fail either check are false positives and must not inflate the report's high-severity observations.

In the rendered report, compare the `API operations` and `Active fuzz probes` metrics with the source run counts. Fuzz cases are evidence, not distinct inventory endpoints, and must not inflate passive candidate counts.

## Stop and escalation conditions

Stop active requests and preserve artifacts when:

- the target returns 429;
- `RateLimit-Remaining` or `X-RateLimit-Remaining` is one or less;
- the request budget cannot cover the full requested range;
- the proxy fails and direct-network fallback would occur;
- redirects or specifications introduce unauthorized hosts;
- response capture truncates; or
- a state-changing candidate requires authority not already granted.

Passive collection/report generation may continue from captured evidence after an active stop. Clearly label the resulting coverage as partial.
