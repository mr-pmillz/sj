# Repository Guidelines

## Project Structure & Module Organization

`sj` is a Go CLI for auditing Swagger/OpenAPI definitions. `cmd/sj/main.go` is the entry point; `internal/cli/` defines Cobra commands and flags. Reusable logic lives under `pkg/`, split into `openapi`, `scanner`, `httpclient`, `brute`, `output`, and `config`. Keep tests beside their packages; `tests/` holds YAML fixtures. The Astro/Starlight site is in `docs/`, with shared images in `img/`.

## Build, Test, and Development Commands

- `go mod download` installs dependencies (Go 1.26.5 is specified in `go.mod`).
- `make build` creates `bin/sj` with version metadata; smoke-test it with `./bin/sj --version`.
- `make test` runs all Go tests with atomic coverage output. It expects `tparse` to be installed.
- `make test-race` reruns the suite with the race detector.
- `make test-coverage` writes coverage reports under `coverage/`.
- `make lint`, `make vet`, and `make fmt` run golangci-lint, `go vet`, and Go/goimports formatting.
- From `docs/`, use `npm ci && npm run dev` for local documentation or `npm run build` for a production check.

## Coding Style & Naming Conventions

Use tabs as produced by `gofmt`, short lowercase package names, `PascalCase` for exported identifiers, and `camelCase` otherwise. Keep CLI wiring in `internal/cli/` and business logic in focused `pkg/` packages. Wrap errors with context using `fmt.Errorf("operation: %w", err)`. Run `make fmt` and `make lint` before submitting; rules are in `.golangci-lint.yml`.

## Testing Guidelines

Use Go's `testing` package and table-driven cases. Name files `*_test.go` and functions `TestBehavior`; use subtests for input variants. Add shared OpenAPI fixtures to `tests/`. No fixed coverage threshold is documented, but exercise changed behavior and run `make test-race` for concurrent code.

## Commit & Pull Request Guidelines

Recent history favors imperative Conventional Commit subjects such as `feat: add ...`; also use `fix:`, `refactor:`, `docs:`, or `test:` as appropriate. Branch from `develop` as `feature/...` or `fix/...` and target normal contributions there. Only `develop`, `release/*`, and `hotfix/*` may target `main`. PRs should explain the change, link relevant issues, list verification, and include screenshots for visible documentation changes. Ensure build, tests, and lint pass.

## Security & Responsible Use

Scanner changes may send real network requests. Test only against systems you are authorized to assess, keep destructive-path safeguards intact, and never commit credentials, private targets, or captured API data.
