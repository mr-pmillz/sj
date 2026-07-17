# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

sj (Swagger Jacker) is a Go CLI tool for auditing exposed Swagger/OpenAPI definition files. It checks API endpoints for weak authentication, generates manual testing commands, discovers hidden spec files via brute-force, and converts between spec versions. Module: `github.com/mr-pmillz/sj`.

## Build & Test Commands

```bash
make build              # Build binary to bin/sj (ldflags inject version from git)
make test               # Run tests with tparse formatting (needs tparse installed)
go test ./... -count=1  # Run all tests without tparse
go test ./pkg/brute/ -v -run TestWriteCSV  # Run a single test
make test-race          # Run tests with race detector
make test-coverage      # Generate HTML coverage report in coverage/
make lint               # Run golangci-lint (config: .golangci-lint.yml)
make fmt                # gofmt + goimports
go vet ./...            # Static analysis
go build ./cmd/sj       # Quick build without ldflags
```

## Architecture

Entry point is `cmd/sj/main.go` → calls `internal/cli.Execute()`.

**Version injection**: `version.go` at module root defines `var version, commit, date` — set by ldflags in Makefile and `.goreleaser.yaml` via `-X github.com/mr-pmillz/sj.version=...`.

### Package Dependency Graph

```
cmd/sj/main.go → internal/cli
                    ↓
    ┌───────────────┼───────────────┐
    ↓               ↓               ↓
pkg/scanner    pkg/brute       pkg/openapi
    ↓               ↓               ↓
pkg/httpclient  pkg/openapi    pkg/config
    ↓               ↓
pkg/config     pkg/output
    ↓
pkg/output
```

Dependencies are strictly acyclic. `pkg/` packages never import `internal/cli`.

### Key Packages

- **`internal/cli/`** — Cobra command definitions. Each command's `Run` sets `cfg.Mode`, creates service objects, calls into `pkg/`. Shared spec-loading logic in `spec.go`. The single `cfg` variable (package-level `*config.Config`) is the only mutable state; flags bind directly to its fields.

- **`pkg/config/`** — Central `Config` struct holding all flag values and runtime state. `Mode` enum replaces the old `os.Args[1]` dispatch pattern. Constructed via `config.New()` with functional options.

- **`pkg/httpclient/`** — `Client` struct wrapping `*http.Client` (pointer, not value). Handles proxy, TLS, random user-agent rotation (default behavior), redirect following, and dangerous keyword detection. `BruteFetch` is a simplified GET for brute-force scanning.

- **`pkg/openapi/`** — Spec parsing (`parse.go`), `$ref` resolution with external file caching (`resolve.go` via `Resolver` struct), schema expansion with allOf/oneOf/anyOf (`schema.go`), JS bundle extraction (`extract.go`), v2→v3 conversion (`convert.go`), and interactive security scheme handling (`auth.go`).

- **`pkg/scanner/`** — `GenerateRequests` orchestrates spec parsing, server/basePath resolution, and dispatches to `BuildRequestsFromPaths` which iterates paths/operations and switches on `cfg.Mode` (automate sends requests, endpoints prints paths, prepare generates curl commands).

- **`pkg/brute/`** — `Scanner` struct for URL discovery. `findAllDefinitionFiles` tests candidate URLs, prints finds immediately to stderr, generates smart path variations (version/extension/sibling swaps in `variations.go`), and stops early once specs are found past the priority URL phase to avoid WAF triggers.

- **`pkg/output/`** — `Writer` struct accumulates results. Supports console (colored), JSON, JSONL, CSV output. `PrintInfo/PrintWarn/PrintErr/Die` are stateless stderr helpers used project-wide.

### How Brute Scanning Works

1. Priority URLs tested first (well-known spec paths)
2. When a spec is found → printed immediately, path variations generated and queued
3. Variation queue drained eagerly after each main URL
4. Once specs found and past priority phase → early stop
5. HTML pages scanned for embedded spec-URL references → queued as variations

### How Automate Scanning Works

1. Spec loaded (URL or local file) → JS bundle unwrapped if needed
2. Security schemes checked (interactive auth prompts unless `--quiet`)
3. Server info / basePath extracted from spec
4. `BuildRequestsFromPaths` iterates paths, expands `$ref` schemas, generates example payloads, sends requests, records results
5. Results output in requested format via `Writer.FinalizeOutput()`

## Conventions

- User-agent is random by default. The `--agent` flag overrides. There is no `--randomize-user-agent` flag.
- Default test string is `"testvalue"`, custom URL is `"https://example.com"`.
- All output/diagnostics go to stderr; only data (spec JSON, endpoint lists, curl commands) goes to stdout.
- Brute output supports: console, json, jsonl, csv, txt formats via `-F` flag.
- Test fixtures live in `tests/` (YAML spec files).
- Docs site uses Astro Starlight in `docs/` — run `cd docs && npm install && npm run dev`.
