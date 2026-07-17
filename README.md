# sj (Swagger Jacker)

![](img/sj-logo.png)

[![CI](https://github.com/mr-pmillz/sj/actions/workflows/ci.yml/badge.svg)](https://github.com/mr-pmillz/sj/actions/workflows/ci.yml)
[![Release](https://github.com/mr-pmillz/sj/actions/workflows/release.yml/badge.svg)](https://github.com/mr-pmillz/sj/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/mr-pmillz/sj)](https://go.dev/)
[![License](https://img.shields.io/github/license/mr-pmillz/sj)](LICENSE)

sj is a command line tool designed to assist with auditing exposed Swagger/OpenAPI definition files by checking the associated API endpoints for weak authentication. It also provides command templates for manual vulnerability testing.

It parses definition files for paths, parameters, and accepted methods, then uses the results with one of five sub-commands:

| Command | Description |
|---------|-------------|
| `automate` | Crafts requests to each endpoint and analyzes the response status code |
| `prepare` | Generates curl/sqlmap commands for manual testing |
| `endpoints` | Lists raw API routes (no parameter substitution) |
| `brute` | Discovers hidden definition files via common file paths |
| `convert` | Converts Swagger v2 definitions to OpenAPI v3 |

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

### Automate

Send requests to each discovered endpoint and analyze responses:

```bash
sj automate -u https://petstore.swagger.io/v2/swagger.json -qi
```

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

Enable verbose output to see response previews:

```bash
sj automate -u https://petstore.swagger.io/v2/swagger.json -qi -v
```

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
sj brute -U targets.txt -qi -F json -o results.json
```

### Convert

Convert a Swagger v2 file to OpenAPI v3:

```bash
sj convert -u https://petstore.swagger.io/v2/swagger.json -o openapi.json
```

## Key Features

- **Random User-Agent** — Uses a random browser User-Agent by default for stealth. Override with `--agent`.
- **Replay Proxy** — Route matched requests through a separate proxy while scanning through another (or direct).
- **Multi-format Output** — Export results as JSON, JSONL, or CSV with `-F` and `-o` flags.
- **Batch Brute Forcing** — Scan multiple targets from a file with `-U`.
- **Dangerous Keyword Detection** — Warns before testing endpoints with potentially destructive operations (override with `--force` or `--accept-risk`).

## Global Flags

```
  -A, --agent string            Set the User-Agent string. Random by default.
  -b, --base-path string        Set the API base path if not defined in the definition file.
  -c, --custom-url string       Set a custom URL for discovered URL parameters. (default "https://example.com")
  -d, --custom-date string      A custom date for discovered date parameters. (default "1990-01-01")
      --custom-email string     A custom email for discovered email parameters. (default "noreply@localhost.localdomain")
      --force                   Send requests without prompting for dangerous keywords.
  -f, --format string           Definition file format: json/yaml/yml/js. (default "json")
  -H, --headers stringArray     Custom headers ("Name: Value"). Multiple flags accepted.
  -i, --insecure                Ignore server certificate validation.
  -l, --local-file string       Load documentation from a local file.
  -o, --outfile string          Output results to a file.
  -p, --proxy string            Proxy host and port. (default "NOPROXY")
      --replay-proxy string     Replay matched requests using this proxy.
  -q, --quiet                   No interactive prompts — use defaults for all requests.
  -s, --safe-word stringArray   Skip dangerous word check for specified word(s).
  -T, --target string           Manually set request target if different from the documentation host.
  -t, --timeout int             Request timeout in seconds. (default 30)
  -u, --url string              Load documentation from a URL.
```

## Project Structure

```
sj/
├── cmd/sj/main.go           # Entry point
├── internal/cli/             # Cobra command wiring
├── pkg/
│   ├── config/               # Central configuration
│   ├── httpclient/           # HTTP client with random UA
│   ├── openapi/              # Spec parsing, schema resolution
│   ├── output/               # Multi-format result output
│   ├── scanner/              # Request building & scanning
│   └── brute/                # Brute-force URL discovery
├── docs/                     # Astro Starlight documentation
└── tests/                    # Test fixtures
```

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/mr-pmillz/sj).

## License

See [LICENSE](LICENSE) for details.
