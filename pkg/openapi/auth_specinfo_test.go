package openapi

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/output"
)

func captureOpenAPIProcessOutput(t *testing.T, run func()) (string, string) {
	t.Helper()

	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		t.Fatal(err)
	}

	originalStdout, originalStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdoutWriter, stderrWriter
	defer func() {
		os.Stdout, os.Stderr = originalStdout, originalStderr
		_ = stdoutReader.Close()
		_ = stderrReader.Close()
	}()

	run()
	if err := stdoutWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stderrWriter.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = originalStdout, originalStderr

	stdout, err := io.ReadAll(stdoutReader)
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := io.ReadAll(stderrReader)
	if err != nil {
		t.Fatal(err)
	}
	return string(stdout), string(stderr)
}

func TestCheckSecuritySchemesReportsSupportedTypesSafelyAndInOrder(t *testing.T) {
	spec := map[string]any{
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"g-non-map": "ignored",
				"f-unknown": map[string]any{"type": "custom"},
				"e-mtls":    map[string]any{"type": "mutualTLS"},
				"d-oidc":    map[string]any{"type": "openIdConnect"},
				"c-oauth":   map[string]any{"type": "oauth2"},
				"b-http":    map[string]any{"type": "http", "scheme": "bearer\r"},
				"a-basic":   map[string]any{"type": "basic"},
				"z\napi": map[string]any{
					"type": "apiKey",
					"in":   "header\x1b",
					"name": "X-API-Key\n",
				},
			},
		},
	}

	_, stderr := captureOpenAPIProcessOutput(t, func() {
		CheckSecuritySchemes(spec, config.New())
	})

	for _, fragment := range []string{
		"Security schemes declared: a-basic, b-http, c-oauth, d-oidc, e-mtls, f-unknown, g-non-map, z\\u000aapi",
		"a-basic uses HTTP Basic authentication",
		"b-http uses HTTP bearer\\u000d authentication",
		"c-oauth uses oauth2",
		"d-oidc uses openIdConnect",
		"e-mtls uses mutualTLS",
		`f-unknown has type "custom"`,
		"z\\u000aapi expects API key X-API-Key\\u000a in header\\u001b",
	} {
		if !strings.Contains(stderr, fragment) {
			t.Errorf("security report missing %q:\n%s", fragment, stderr)
		}
	}
	if strings.ContainsAny(stderr, "\r\x1b") {
		t.Fatalf("security report contains raw terminal control characters: %q", stderr)
	}
}

func TestCheckSecuritySchemesWarnsWhenNoneAreDefined(t *testing.T) {
	_, stderr := captureOpenAPIProcessOutput(t, func() {
		CheckSecuritySchemes(map[string]any{}, config.New())
	})
	if !strings.Contains(stderr, "No security schemes are defined") {
		t.Fatalf("missing no-security warning: %q", stderr)
	}
}

func TestSecuritySchemesSupportsSwaggerTwoAndPrefersOpenAPIThree(t *testing.T) {
	legacy := map[string]any{"legacy": map[string]any{"type": "basic"}}
	modern := map[string]any{"modern": map[string]any{"type": "http"}}

	if got := securitySchemes(map[string]any{"securityDefinitions": legacy}); len(got) != 1 || got["legacy"] == nil {
		t.Fatalf("Swagger 2 schemes = %#v", got)
	}
	got := securitySchemes(map[string]any{
		"components":          map[string]any{"securitySchemes": modern},
		"securityDefinitions": legacy,
	})
	if len(got) != 1 || got["modern"] == nil {
		t.Fatalf("OpenAPI 3 schemes = %#v", got)
	}
}

func TestPrintSpecInfoRoutesStructuredAndConsoleOutputSafely(t *testing.T) {
	spec := map[string]any{"info": map[string]any{
		"title":       "Control\x1b[2J title",
		"description": "line one\nline two",
	}}

	consoleWriter := output.NewWriter(config.New())
	stdout, stderr := captureOpenAPIProcessOutput(t, func() {
		PrintSpecInfo(spec, consoleWriter, consoleWriter.Cfg)
	})
	if stderr != "" {
		t.Fatalf("console metadata unexpectedly written to stderr: %q", stderr)
	}
	if !strings.Contains(stdout, `Title: Control\u001b[2J title`) ||
		!strings.Contains(stdout, `Description: line one\u000aline two`) {
		t.Fatalf("console metadata was not terminal-safe: %q", stdout)
	}
	if consoleWriter.SpecTitle != "Control\x1b[2J title" || consoleWriter.SpecDescription != "line one\nline two" {
		t.Fatalf("writer metadata = %q / %q", consoleWriter.SpecTitle, consoleWriter.SpecDescription)
	}

	structuredCfg := config.New()
	structuredCfg.OutputFormat = "JSONL"
	structuredWriter := output.NewWriter(structuredCfg)
	stdout, stderr = captureOpenAPIProcessOutput(t, func() {
		PrintSpecInfo(spec, structuredWriter, structuredCfg)
	})
	if stdout != "" {
		t.Fatalf("structured metadata unexpectedly written to stdout: %q", stdout)
	}
	if !strings.Contains(stderr, `Title: Control\u001b[2J title`) ||
		!strings.Contains(stderr, `Description: line one\u000aline two`) {
		t.Fatalf("structured metadata was not reported safely: %q", stderr)
	}
}

func TestPrintSpecInfoHandlesMissingAndEmptyFields(t *testing.T) {
	writer := output.NewWriter(config.New())
	_, stderr := captureOpenAPIProcessOutput(t, func() {
		PrintSpecInfo(map[string]any{}, writer, writer.Cfg)
	})
	if !strings.Contains(stderr, "No information defined") {
		t.Fatalf("missing-info report = %q", stderr)
	}

	stdout, stderr := captureOpenAPIProcessOutput(t, func() {
		PrintSpecInfo(map[string]any{"info": map[string]any{"title": 42, "description": ""}}, writer, writer.Cfg)
	})
	if stdout != "" || stderr != "" || writer.SpecTitle != "" || writer.SpecDescription != "" {
		t.Fatalf("empty metadata produced output=%q stderr=%q writer=%#v", stdout, stderr, writer)
	}
}

func TestOpenAPIURLAndFormatHelpersCoverBoundaryCases(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{"", ""},
		{"/", ""},
		{"  api/v1/// ", "/api/v1"},
		{"/api/v1/", "/api/v1"},
	} {
		if got := NormalizeBasePath(test.input); got != test.want {
			t.Errorf("NormalizeBasePath(%q) = %q, want %q", test.input, got, test.want)
		}
	}

	if got := SetScheme("http://api.example.test/spec"); got != "http" {
		t.Errorf("SetScheme(http) = %q", got)
	}
	for _, target := range []string{"https://api.example.test/spec", "HTTP://api.example.test/spec", "api.example.test"} {
		if got := SetScheme(target); got != "https" {
			t.Errorf("SetScheme(%q) = %q", target, got)
		}
	}

	for _, test := range []struct {
		target string
		host   string
		want   string
	}{
		{"http://api.example.test", "ignored", "api.example.test"},
		{"https://api.example.test", "ignored", "api.example.test"},
		{"api.example.test", "ignored", "api.example.test"},
		{"", "fallback.example.test", "fallback.example.test"},
	} {
		if got := TrimHostScheme(test.target, test.host); got != test.want {
			t.Errorf("TrimHostScheme(%q, %q) = %q, want %q", test.target, test.host, got, test.want)
		}
	}
}

func TestLooksLikeJSSpecRecognizesHintsAndContentPrefixes(t *testing.T) {
	for _, test := range []struct {
		name       string
		body       []byte
		swaggerURL string
		localFile  string
		format     string
		want       bool
	}{
		{name: "URL suffix", swaggerURL: "https://example.test/SPEC.JS", want: true},
		{name: "file suffix", localFile: "/tmp/spec.Js", want: true},
		{name: "format", format: "JS", want: true},
		{name: "var", body: []byte("\n var spec = {};"), want: true},
		{name: "let", body: []byte("let spec = {};"), want: true},
		{name: "const", body: []byte("const spec = {};"), want: true},
		{name: "function", body: []byte("(function () {})();"), want: true},
		{name: "window", body: []byte("window.spec = {};"), want: true},
		{name: "line comment", body: []byte("// spec"), want: true},
		{name: "block comment", body: []byte("/* spec */"), want: true},
		{name: "plain JSON", body: []byte(`{"openapi":"3.1.0"}`), want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := LooksLikeJSSpec(test.body, test.swaggerURL, test.localFile, test.format); got != test.want {
				t.Fatalf("LooksLikeJSSpec() = %v, want %v", got, test.want)
			}
		})
	}
}
