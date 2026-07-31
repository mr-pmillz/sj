# sj (Swagger Jacker)

![](img/sj-logo.png)

[![CI](https://github.com/mr-pmillz/sj/actions/workflows/ci.yml/badge.svg)](https://github.com/mr-pmillz/sj/actions/workflows/ci.yml)
[![Release](https://github.com/mr-pmillz/sj/actions/workflows/release.yml/badge.svg)](https://github.com/mr-pmillz/sj/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/mr-pmillz/sj)](https://go.dev/)
[![License](https://img.shields.io/github/license/mr-pmillz/sj)](LICENSE)
[![Plumber Score](https://score.getplumber.io/github.com/mr-pmillz/sj.svg)](https://score.getplumber.io/github.com/mr-pmillz/sj)

sj is a command line tool designed to assist with auditing exposed Swagger/OpenAPI definition files by checking the associated API endpoints for weak authentication. It also provides command templates for manual vulnerability testing.

It parses Swagger 2.0 and OpenAPI 3.0–3.2 definitions, including modern JSON Schema, server overrides, webhooks, `QUERY`, and additional operations. Core subcommands include:

| Command               | Description                                                                                      |
|-----------------------|--------------------------------------------------------------------------------------------------|
| `audit`               | Passively finds authentication, transport, and contract risks; supports JSON and SARIF           |
| `automate`            | Crafts requests to each endpoint and analyzes the response status code                           |
| `prepare`             | Generates curl/sqlmap commands for manual testing                                                |
| `endpoints`           | Lists raw API routes (no parameter substitution)                                                 |
| `brute`               | Discovers hidden definition files via common file paths                                          |
| `convert`             | Converts Swagger v2 definitions to OpenAPI v3                                                    |
| `collection`          | Generates populated Bruno API penetration-testing collections from automate results              |
| `fuzz`                | Runs rate-safe active API mutation, identity-comparison, PII, enumeration, and error checks      |
| `report`              | Builds terminal, Markdown, and HTML API penetration-test reports                                 |
| `run --full-workflow` | Chains authorized recon, enumeration, bounded exploitation, collection generation, and reporting |
| `runs`                | Lists runs in the default-on SQLite result database                                              |
| `mcp`                 | Starts an optional, policy-constrained MCP server for AI agents                                  |

## Installation

### Go Install

```bash
go install github.com/mr-pmillz/sj/cmd/sj@latest
```

### Build from Source

```bash
git clone https://github.com/mr-pmillz/sj.git
cd sj/
make build
```

The binary will be at `bin/sj`.

### Docker

```bash
docker pull ghcr.io/mr-pmillz/sj:latest
docker run --rm ghcr.io/mr-pmillz/sj:latest --help
```

## Usage

### Audit

Run a passive contract and security review without calling documented API operations:

```bash
sj audit -l ./openapi.yaml -f yaml --fail-on high
sj audit -u https://example.com/openapi.json -F sarif -o sj.sarif
```

### Automate

Send requests to each discovered endpoint and analyze responses:

```bash
sj automate -u https://petstore.swagger.io/v2/swagger.json -qi
```

By default, active scanning sends only `GET`, `HEAD`, `OPTIONS`, and OpenAPI 3.2 `QUERY` operations. Add `--accept-risk` (or the broader `--force`) only when you are authorized to send state-changing methods.

```
Gathering API details.
Title: Swagger Petstore
Description: This is a sample server Petstore server.
✓  GET  200  /v2/pet/findByStatus
✓  GET  200  /v2/user/logout
⚠  POST  400  /v2/user/createWithArray
⚠  POST  400  /v2/store/order
✗  GET  404  /v2/store/order/1
✓  GET  200  /v2/store/inventory
✓  GET  200  /v2/user/login
```

Replay matched requests through a separate proxy (e.g., Burp Suite):

```bash
sj automate -u https://petstore.swagger.io/v2/swagger.json -qi --replay-proxy http://127.0.0.1:8080
```

Route any command through an anonymous or authenticated SOCKS5 proxy:

```bash
sj brute -u https://target.example.com \
  --socks5-proxy socks5://127.0.0.1:9050

sj automate -u https://target.example.com/openapi.json \
  --socks5-proxy socks5://proxy.example.com:1080 \
  --socks5-username audit-user \
  --socks5-password "$SOCKS5_PASSWORD"
```

SOCKS5 and HTTP `--proxy` settings are mutually exclusive. Credentials must be supplied with the dedicated flags rather than embedded in the proxy URL.

Enable verbose output to see response previews:

```bash
sj automate -u https://petstore.swagger.io/v2/swagger.json -qi -v
```

Structured output always records the resolved operation URL and populated sample request body. Response bodies are opt-in, private, and bounded:

```bash
sj automate -U discovered.json -F json -o results.json \
  --store-responses --max-stored-response-bytes 65536
```

Credential-like request headers and JSON fields are redacted from stored curl/request evidence.

Scan specification URLs from a text file, or feed `brute` output directly into `automate`:

```bash
sj automate -U specification-urls.txt -F json -o results.json

sj brute -U targets.txt -F json -o discovered.json
sj automate -U discovered.json -F json -o results.json

# Consume the database run ID printed by brute without an intermediate file.
sj automate --brute-run BRUTE_RUN_ID -F json -o results.json
```

`automate -U` accepts one specification URL per line plus the JSON and JSONL formats emitted by `brute`. Duplicate URLs are scanned once and batch results include their source specification.

Exclude methods before request planning and improve interactive output:

```bash
sj automate -U discovered.json --exclude DELETE,PUT --full-urls --color always
```

`--exclude` is case-insensitive and may be repeated. `--color` accepts `auto`, `always`, or `never`; color and full URLs affect terminal/progress presentation without changing structured result targets.

### Prepare

Generate commands for manual testing (supports `curl` and `sqlmap`):

```bash
sj prepare -u https://petstore.swagger.io/v2/swagger.json -qi
```

### Endpoints

List raw API routes from a definition file:

```bash
sj endpoints -u https://petstore.swagger.io/v2/swagger.json -qi
```

### Brute

Discover hidden definition files on a target:

```bash
sj brute -u https://petstore.swagger.io -qi -e
```

Scan multiple targets from a file:

```bash
sj brute -U targets.txt --workers 8 -qi -F json -o results.json
```

`brute` follows same-origin Swagger UI, Redoc, Swashbuckle, initializer JavaScript, and JSON configuration references with bounded depth and fan-out. Cross-origin, credential-bearing, and non-HTTP references are rejected before network I/O. Browser/WAF challenges, sustained-challenge stops after prioritized candidate coverage, rate-limit stops, repeated equivalent 502/503/504 stops, policy rejections, traversal-limit skips, and repeated wildcard HTTP 200 responses are reported as explicit coverage signals. Valid OpenAPI documents are never removed by the wildcard filter.

### Bruno penetration-test collections

Generate a full baseline collection plus bounded IDOR/object enumeration, username enumeration, verbose-error, PII review, identity-comparison, and workflow support:

```bash
sj collection --input targets/results --scope all \
  --known-username authorized-test-user \
  -o api-pentest-bruno

sj collection --run AUTOMATE_RUN_ID -o api-pentest-bruno
```

State-changing Bruno requests contain a pre-request guard. The generated environment uses credential placeholders, provides Identity A/B variables, and keeps bounded payload dictionaries under `payloads/`.

### Bounded API fuzzing

Fuzz interesting operations (the default), all operations, IDOR candidates, or explicit endpoints:

```bash
sj fuzz --run AUTOMATE_RUN_ID --scope interesting \
  --identity-header 'admin=Authorization: Bearer ADMIN_TOKEN' \
  --identity-header 'user=Authorization: Bearer USER_TOKEN' \
  --known-username authorized-test-user \
  --max-requests 200 --delay 500ms --color always

sj fuzz -I automate.json --scope all -F json -o fuzz.json
sj fuzz -I automate.json --endpoint 'GET https://api.example/users/1'
sj fuzz --run AUTOMATE_RUN_ID --scope idor --idor-range 1-100 \
  --max-cases 4096 --max-requests 10000 --delay 500ms \
  --store-responses --max-stored-response-bytes 1073741824 \
  -F json -o idor-fuzz.json
```

Numeric IDOR ranges are inclusive and limited to 1,000 values. sj mutates every identifier-bearing path segment, query parameter, and top-level JSON property, rejects a partial range when `--max-cases` is too small, and reports a high-severity active-test candidate only when multiple successful IDs have distinct response hashes. Identical wildcard/catch-all responses are not reported as differential IDOR evidence.

`fuzz` is sequential, enforces a hard request budget and bounded payload/response sizes, and stops immediately on HTTP 429 or a near-empty advertised rate budget. It returns an incomplete-coverage error if `--max-requests` prevents every planned case from running. It does not generate oversized, recursive, sleep, resource-exhaustion, or denial-of-service payloads. State-changing operations require `--accept-risk`.

Complete business workflows and persisted side-effect verification are explicit rather than guessed. Supply a generated or hand-reviewed workflow file whose steps can capture JSON values, substitute them into later requests, compare named identities, assert status/JSON values, and mark read-back steps with `verify_side_effect`:

```bash
sj fuzz --workflow workflow.json --accept-risk --max-requests 50 --delay 1s
```

### Convert

Convert a Swagger v2 file to OpenAPI v3:

```bash
sj convert -u https://petstore.swagger.io/v2/swagger.json -o openapi.json
```

### API penetration-test reports

Generate Markdown and self-contained HTML reports from a directory containing `sj brute` and `sj automate` JSON, JSONL, CSV, and brute TXT results:

```bash
sj report --input targets/results -O -o targets/results/api-pentest-report --color always
sj report --run BRUTE_RUN_ID --run AUTOMATE_RUN_ID --run FUZZ_RUN_ID -O -o api-pentest-report
```

The report deduplicates equivalent output formats and includes HTTP, method, and specification-host distributions; wildcard-response filtering and coverage metrics; weighted critical/high/medium/low/informational findings; stored fuzz evidence; and OWASP API Security Top 10 (2023) review guidance. HTML findings include native, toggleable request/response proof blocks when response capture was enabled. Target-controlled markup is escaped, and incomplete evidence is labeled as truncated. Use `--max-evidence` to control the number of proof records attached to each finding. IDOR, business-logic, SSRF, and resource-consumption entries are explicitly labeled as testing candidates unless active evidence supports a stronger conclusion.

### Full assessment workflow

Run discovery, endpoint enumeration, bounded numeric IDOR testing, Bruno generation, and Markdown/HTML reporting as one artifact-producing workflow:

```bash
sj --socks5-proxy socks5://127.0.0.1:9000 \
  --database targets/results/authorized-qa.db \
  --max-response-bytes 1073741824 \
  -o targets/results/full-workflow \
  run --full-workflow --url-file targets/unique-base-urls.txt \
  --workers 20 --exclude DELETE --idor-range 1-100 \
  --max-cases 4096 --max-fuzz-requests 10000 --delay 500ms
```

The output directory must not already exist. DELETE is always excluded, response capture is enabled for automate and fuzz with the configured response read limit, and SQLite storage remains enabled. Non-DELETE state-changing requests still require `--accept-risk`. A rate-limit signal stops active fuzzing immediately; already captured artifacts are still used to generate the Bruno collection and final reports.

### Manifest-driven authorization assessments

Build an offline, deterministic ownership matrix from a local OpenAPI contract, two or more named identities, and explicitly owned test objects:

```bash
export SJ_ASSESSMENT_EVIDENCE_KEY="$(openssl rand -base64 32)"
export SJ_USER_A_TOKEN='Bearer replace-from-secret-manager'
export SJ_USER_B_TOKEN='Bearer replace-from-secret-manager'

sj assess plan --manifest assessment.yaml
sj --database authorized-assessment.db assess run --manifest assessment.yaml
sj --database authorized-assessment.db assess status --id ASSESSMENT_ID
sj --database authorized-assessment.db \
  assess report --id ASSESSMENT_ID --output-format html > assessment.html
```

`assess` rejects remote inputs during offline planning, literal credentials, wildcard scope, destructive methods, unsafe payload classes, unbudgeted redirects, and unsigned resume state. The initial runtime executes read-only BOLA/IDOR proof matrices with victim-own, attacker-own, cross-owner, anonymous, and nonexistent-object controls. Confirmed findings require established ownership, an expected deny policy, repeated stable victim-specific evidence, and a distinct successful negative control. See the [assess command guide](https://mr-pmillz.github.io/sj/commands/assess/) for the manifest and lifecycle.

Assessment HTML reports use offline, independently searchable/sortable/paginated tables with a persistent light/dark toggle. False-positive control outcomes are suppressed from Findings and Comparisons instead of being presented as vulnerabilities. When a manifest explicitly enables `storeResponseBodies` and `includeSensitiveExports`, request/response exchanges are stored as bounded AES-256-GCM artifacts and rendered as actual evidence after integrity verification; credential-bearing headers are omitted. Treat these HTML files as sensitive and keep them mode `0600`.

### SQLite result database

Result storage is enabled by default for `audit`, `automate`, `brute`, `collection`, `convert`, `endpoints`, `fuzz`, `prepare`, and `report`. Each invocation creates an immutable run ID and stores typed observations/findings in a private, versioned SQLite database. The default lives under the user configuration directory, or `$XDG_DATA_HOME/sj/results.db` when that variable is set.

```bash
sj runs
sj runs --json --limit 20
sj brute -u https://target.example --database ./authorized-qa.db
sj automate --brute-run RUN_ID --database ./authorized-qa.db
```

Use `--database PATH` to select another database or `--no-database` for an intentionally ephemeral invocation. Response bodies remain opt-in with `--store-responses`; result metadata and redacted request evidence are stored by default.

### MCP Server

Expose typed `sj` tools to an MCP client over standard input/output:

```json
{
  "mcpServers": {
    "sj": {
      "command": "/absolute/path/to/sj",
      "args": ["mcp", "--allow-host", "api.example.com", "--allow-active"]
    }
  }
}
```

The server provides passive audit, request-planning, and conversion tools plus opt-in single-target and batch scanning and definition discovery. The `brute_openapi` tool supports bounded target-level workers, and `automate_openapi` accepts its structured reports directly. Batch automation deduplicates identical operation plans and supports method exclusions, complete response capture, full-URL progress, and `auto`, `always`, or `never` color modes. Remote access requires at least one `--allow-host`; local files require `--allow-local-files`; state-changing requests require both `--allow-active` and `--allow-destructive`. Protocol input, structured output, result counts, workers, and concurrent calls are bounded. Run `sj mcp --help` for policy controls.

## Key Features

- **OpenAPI 3.2 Support** — Handles `QUERY`, `additionalOperations`, `querystring` parameters, webhooks, callbacks, modern JSON Schema keywords, and layered server/parameter overrides.
- **Passive Security Audit** — Reports risky authentication, plaintext servers, anonymous operations, path-contract errors, and callback/webhook surfaces as console, JSON, or SARIF.
- **Safe Active Defaults** — Skips state-changing methods unless risk is explicitly accepted and bounds specifications, responses, wordlists, and retries.
- **Random User-Agent** — Uses a random browser User-Agent by default for stealth. Override with `--agent`.
- **Replay Proxy** — Route matched requests through a separate proxy while scanning through another (or direct).
- **SOCKS5 Proxies** — Route every command through anonymous or username/password-authenticated SOCKS5 with remote hostname resolution.
- **Multi-format Output** — Export results as JSON, JSONL, or CSV with `-F` and `-o` flags.
- **Batch Automation** — Scan URL lists or `brute` JSON/JSONL output directly with `automate -U`.
- **Batch Brute Forcing** — Scan multiple targets from a file with `-U`.
- **Bounded UI Discovery** — Follow same-origin documentation UI, initializer, configuration, and specification references while reporting WAF and traversal coverage limits.
- **Default SQLite History** — Query immutable run IDs and reuse stored brute/automate/fuzz results without intermediate files.
- **Bruno Collections** — Generate populated API penetration-test requests, bounded payload dictionaries, identity comparisons, and workflow templates.
- **Rate-Safe API Fuzzing** — Run bounded object/username enumeration, identity comparisons, PII checks, verbose-error checks, and explicit read-back workflows.
- **Ownership-Backed Assessments** — Build signed, resumable BOLA proof matrices from exact scope, named identities, owned fixtures, expected deny rules, and worst-case traffic budgets.
- **API Ecosystem Inventory** — Normalize OpenAPI, sj results, HAR, Burp XML, Postman, and gateway logs while identifying shadow, zombie, version-drift, and enumeration candidates without granting active scope.
- **Protocol-Aware Planning** — Bound GraphQL depth/aliases/complexity and WebSocket/AsyncAPI message authorization cases without generating introspection, flooding, or denial-of-service traffic.
- **Wildcard-200 Detection** — Suppress repeated web-server fallback responses from brute discovery results.
- **API Penetration-Test Reports** — Consolidate prior scan results into terminal, Markdown, and self-contained HTML reports with weighted triage and OWASP API mappings.
- **Dangerous Keyword Detection** — Warns before testing endpoints with potentially destructive operations (override with `--force` or `--accept-risk`).
- **MCP Server** — Lets AI agents use typed, structured audit tools over stdio with host allowlists, local-file isolation, active/destructive gates, cancellation, and bounded results.

## Global Flags

```
  -A, --agent string            Set the User-Agent string. Random by default.
  -b, --base-path string        Set the API base path if not defined in the definition file.
  -c, --custom-url string       Set a custom URL for discovered URL parameters. (default "https://example.com")
  -d, --custom-date string      A custom date for discovered date parameters. (default "1990-01-01")
      --custom-email string     A custom email for discovered email parameters. (default "noreply@localhost.localdomain")
      --force                   Bypass method and dangerous-keyword safety checks.
      --database string         SQLite result database path. Enabled by default.
      --no-database             Disable SQLite result storage for this command.
  -f, --format string           Definition file format: json/yaml/yml/js. (default "json")
  -H, --headers stringArray     Custom headers ("Name: Value"). Multiple flags accepted.
  -i, --insecure                Ignore server certificate validation.
  -l, --local-file string       Load documentation from a local file.
  -o, --outfile string          Output results to a file.
  -p, --proxy string            Proxy host and port. (default "NOPROXY")
      --replay-proxy string     Replay matched requests using this proxy.
      --socks5-proxy string     Route requests through a SOCKS5 proxy URL.
      --socks5-username string  Username for SOCKS5 authentication.
      --socks5-password string  Password for SOCKS5 authentication.
  -q, --quiet                   Use non-interactive defaults; credentials are never prompted for.
  -s, --safe-word stringArray   Skip dangerous word check for specified word(s).
  -T, --target string           Manually set request target if different from the documentation host.
  -t, --timeout int             Request timeout in seconds. (default 30)
      --max-response-bytes int  Maximum response body size per request. (default 10485760)
      --max-spec-bytes int      Maximum loaded specification size. (default 10485760)
  -u, --url string              Load documentation from a URL.
```

## Project Structure

```
sj/
├── cmd/sj/main.go           # Entry point
├── internal/cli/             # Cobra command wiring
├── pkg/
│   ├── config/               # Central configuration
│   ├── apitest/              # Shared operation selection and bounded payload generation
│   ├── audit/                # Passive security and contract checks
│   ├── bruno/                # Native Bruno penetration-test collection generation
│   ├── fuzz/                 # Bounded active API testing and workflow verification
│   ├── httpclient/           # HTTP client with random UA
│   ├── openapi/              # Spec parsing, schema resolution
│   ├── mcpserver/             # Typed MCP tools and policy enforcement
│   ├── output/               # Multi-format result output
│   ├── report/               # Result ingestion, metrics, severity analysis, and rendering
│   ├── store/                # Versioned SQLite run/result persistence
│   ├── specsource/            # Bounded URL/local specification loading
│   ├── scanner/              # Request building & scanning
│   └── brute/                # Brute-force URL discovery
├── docs/                     # Astro Starlight documentation
└── tests/                    # Test fixtures
```

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/mr-pmillz/sj).

## License

See [LICENSE](LICENSE) for details.
