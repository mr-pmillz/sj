package scanner

import (
	"strings"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/config"
)

// documentBaseCase is one specification and the URL it was fetched from,
// with the origin and base path the test stage configures for it when no
// --target or --base-path is given. An empty wantTarget with wantErr set
// means the test stage refuses the document.
type documentBaseCase struct {
	name         string
	documentURL  string
	spec         map[string]any
	wantTarget   string
	wantBasePath string
	wantErr      string
}

func documentBaseCases() []documentBaseCase {
	server := func(url string) []any { return []any{map[string]any{"url": url}} }
	return []documentBaseCase{
		{
			name: "openapi 3 absolute server on another host", documentURL: "https://docs.example.com/openapi.json",
			spec:       map[string]any{"openapi": "3.1.0", "servers": server("https://api.example.net/v3")},
			wantTarget: "https://api.example.net", wantBasePath: "/v3",
		},
		{
			name: "openapi 3 relative server with a leading slash", documentURL: "https://docs.example.com/specs/openapi.yaml",
			spec:       map[string]any{"openapi": "3.0.3", "servers": server("/api/v1/")},
			wantTarget: "https://docs.example.com", wantBasePath: "/api/v1",
		},
		{
			name: "openapi 3 relative server against the document directory", documentURL: "http://docs.example.com:8080/specs/openapi.yaml",
			spec:       map[string]any{"openapi": "3.0.3", "servers": server("v2")},
			wantTarget: "http://docs.example.com:8080", wantBasePath: "/specs/v2",
		},
		{
			name: "openapi 3 server variables with defaults", documentURL: "https://docs.example.com/openapi.json",
			spec: map[string]any{"openapi": "3.2.0", "servers": []any{map[string]any{
				"url": "https://{tenant}.example.net:{port}/{version}",
				"variables": map[string]any{
					"tenant":  map[string]any{"default": "demo", "enum": []any{"demo", "prod"}},
					"port":    map[string]any{"default": "8443"},
					"version": map[string]any{"default": "v2"},
				},
			}}},
			wantTarget: "https://demo.example.net:8443", wantBasePath: "/v2",
		},
		{
			name: "openapi 3 server naming the scheme's default port", documentURL: "https://docs.example.com/openapi.json",
			spec:       map[string]any{"openapi": "3.1.0", "servers": server("https://api.example.net:443/v1")},
			wantTarget: "https://api.example.net:443", wantBasePath: "/v1",
		},
		{
			name: "openapi 3 only the first server counts", documentURL: "https://docs.example.com/openapi.json",
			spec:       map[string]any{"openapi": "3.1.0", "servers": append(server("https://first.example.net"), map[string]any{"url": "https://second.example.net"})},
			wantTarget: "https://first.example.net", wantBasePath: "",
		},
		{
			name: "openapi 3 without servers uses the document origin", documentURL: "https://docs.example.com/specs/openapi.json",
			spec:       map[string]any{"openapi": "3.1.0"},
			wantTarget: "https://docs.example.com", wantBasePath: "",
		},
		{
			name: "swagger 2 host, schemes and basePath", documentURL: "https://docs.example.com/swagger.json",
			spec:       map[string]any{"swagger": "2.0", "host": "api.example.net:8080", "schemes": []any{"http", "https"}, "basePath": "/v1/"},
			wantTarget: "http://api.example.net:8080", wantBasePath: "/v1",
		},
		{
			name: "swagger 2 host only takes the document scheme", documentURL: "http://docs.example.com/swagger.json",
			spec:       map[string]any{"swagger": "2.0", "host": "api.example.net"},
			wantTarget: "http://api.example.net", wantBasePath: "",
		},
		{
			name: "swagger 2 without host or schemes uses the document origin", documentURL: "https://docs.example.com/v2/swagger.json",
			spec:       map[string]any{"swagger": "2.0", "basePath": "/api"},
			wantTarget: "https://docs.example.com", wantBasePath: "/api",
		},
		{
			name: "swagger 2 root basePath", documentURL: "https://docs.example.com/swagger.json",
			spec:       map[string]any{"swagger": "2.0", "host": "api.example.net", "schemes": []any{"https"}, "basePath": "/"},
			wantTarget: "https://api.example.net", wantBasePath: "",
		},
		{
			name: "server variable without a default", documentURL: "https://docs.example.com/openapi.json",
			spec:    map[string]any{"openapi": "3.1.0", "servers": []any{map[string]any{"url": "https://{tenant}.example.net", "variables": map[string]any{"tenant": map[string]any{}}}}},
			wantErr: "has no string default",
		},
		{
			name: "server with a query", documentURL: "https://docs.example.com/openapi.json",
			spec:    map[string]any{"openapi": "3.1.0", "servers": server("https://api.example.net/v1?key=value")},
			wantErr: "must not contain a query or fragment",
		},
		{
			name: "document URL with a query and no server", documentURL: "https://docs.example.com/openapi.json?format=json",
			spec:    map[string]any{"openapi": "3.1.0"},
			wantErr: "must not contain a query or fragment",
		},
		{
			name: "swagger 2 scheme that is not http", documentURL: "https://docs.example.com/swagger.json",
			spec:    map[string]any{"swagger": "2.0", "host": "api.example.net", "schemes": []any{"ws"}},
			wantErr: "unsupported server URL scheme",
		},
		{
			name: "swagger version that is not a string", documentURL: "https://docs.example.com/swagger.yaml",
			spec:    map[string]any{"swagger": 2.0, "host": "api.example.net"},
			wantErr: "does not declare a supported Swagger or OpenAPI version",
		},
		{
			name: "server that is not an object", documentURL: "https://docs.example.com/openapi.json",
			spec:    map[string]any{"openapi": "3.1.0", "servers": []any{"https://api.example.net"}},
			wantErr: "first server entry is not an object",
		},
	}
}

// TestConfigureTargetResolvesDocumentBases pins what the test stage
// configures for each kind of document when no --target or --base-path is
// given. It passed before the resolution was shared with discovery and must
// keep passing.
func TestConfigureTargetResolvesDocumentBases(t *testing.T) {
	for _, tc := range documentBaseCases() {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.New()
			cfg.Mode = config.ModeAutomate
			cfg.SwaggerURL = tc.documentURL
			err := ConfigureTarget(tc.spec, cfg)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.APITarget != tc.wantTarget || cfg.BasePath != tc.wantBasePath {
				t.Fatalf("target = %q base = %q, want %q and %q", cfg.APITarget, cfg.BasePath, tc.wantTarget, tc.wantBasePath)
			}
		})
	}
}

// TestConfigureTargetKeepsALocalEndpointsDocumentWithoutServer pins the one
// case where the test stage needs no target: listing the endpoints of a local
// document that names no server. Swagger 2 still takes its basePath.
func TestConfigureTargetKeepsALocalEndpointsDocumentWithoutServer(t *testing.T) {
	cfg := config.New()
	cfg.Mode = config.ModeEndpoints
	cfg.LocalFile = "openapi.yaml"
	if err := ConfigureTarget(map[string]any{"swagger": "2.0", "basePath": "/api"}, cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.APITarget != "" || cfg.BasePath != "/api" {
		t.Fatalf("target = %q base = %q", cfg.APITarget, cfg.BasePath)
	}
	cfg = config.New()
	cfg.Mode = config.ModeAutomate
	cfg.LocalFile = "openapi.yaml"
	err := ConfigureTarget(map[string]any{"openapi": "3.1.0"}, cfg)
	if err == nil || !strings.Contains(err.Error(), "use --target for a local specification") {
		t.Fatalf("error = %v, want the local specification refusal", err)
	}
}

// TestConfigureTargetTerminatesOnServerVariableDefaultsThatNameVariables
// holds the substitution to one pass: a default that itself names a variable
// is inserted as written and never expanded again. Discovery resolves the
// base of every document it finds, so a document must not be able to hang it.
func TestConfigureTargetTerminatesOnServerVariableDefaultsThatNameVariables(t *testing.T) {
	tests := map[string]map[string]any{
		"default naming itself in the host": {"url": "https://{a}.example.net", "variables": map[string]any{"a": map[string]any{"default": "{a}"}}},
		"default naming itself twice":       {"url": "https://api.example.net/{a}", "variables": map[string]any{"a": map[string]any{"default": "{a}{a}"}}},
		"defaults naming each other":        {"url": "https://api.example.net/{a}", "variables": map[string]any{"a": map[string]any{"default": "{b}"}, "b": map[string]any{"default": "{a}"}}},
	}
	for name, server := range tests {
		t.Run(name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() {
				cfg := config.New()
				cfg.SwaggerURL = "https://docs.example.com/openapi.json"
				done <- ConfigureTarget(map[string]any{"openapi": "3.1.0", "servers": []any{server}}, cfg)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("server variable expansion did not terminate")
			}
		})
	}
}

// TestDocumentAPIBaseWritesTheBaseItsTestStageUses holds the written form of
// the API base: the test stage's origin and base path, without a port that
// is the scheme's default, escaped as a URL.
func TestDocumentAPIBaseWritesTheBaseItsTestStageUses(t *testing.T) {
	tests := map[string]struct {
		server string
		want   string
	}{
		"https default port":            {server: "https://api.example.net:443/v1", want: "https://api.example.net/v1"},
		"http default port":             {server: "http://api.example.net:80", want: "http://api.example.net"},
		"another scheme's default port": {server: "https://api.example.net:80/v1", want: "https://api.example.net:80/v1"},
		"empty port":                    {server: "https://api.example.net:/v1", want: "https://api.example.net/v1"},
		"other port":                    {server: "http://api.example.net:8080/v1/", want: "http://api.example.net:8080/v1"},
		"IPv6 default port":             {server: "https://[2001:db8::1]:443/v1", want: "https://[2001:db8::1]/v1"},
		"IPv6 zone":                     {server: "http://[fe80::1%25eth0]:8080/v1", want: "http://[fe80::1%25eth0]:8080/v1"},
		"escaped path":                  {server: "https://api.example.net/a%20b/", want: "https://api.example.net/a%20b"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			spec := map[string]any{"openapi": "3.1.0", "servers": []any{map[string]any{"url": tc.server}}}
			got, err := documentSpecAPIBase(spec, "https://docs.example.com/openapi.json")
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("api base = %q, want %q", got, tc.want)
			}
			cfg := config.New()
			cfg.SwaggerURL = "https://docs.example.com/openapi.json"
			if err := ConfigureTarget(spec, cfg); err != nil {
				t.Fatalf("the test stage refuses a server discovery resolves: %v", err)
			}
		})
	}
}
