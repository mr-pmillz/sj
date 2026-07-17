package audit

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestAnalyzeModelsSecurityAlternativesAndOpenAPI32Surfaces(t *testing.T) {
	spec := map[string]any{
		"openapi": "3.2.0",
		"info":    map[string]any{"title": "Payments"},
		"servers": []any{map[string]any{"url": "http://api.example"}},
		"components": map[string]any{"securitySchemes": map[string]any{
			"queryKey": map[string]any{"type": "apiKey", "in": "query", "name": "key"},
		}},
		"security": []any{map[string]any{"queryKey": []any{}}},
		"paths": map[string]any{
			"/payments/{id}": map[string]any{
				"parameters":           []any{map[string]any{"name": "id", "in": "path", "required": true}},
				"get":                  map[string]any{"operationId": "getPayment", "security": []any{map[string]any{}}},
				"additionalOperations": map[string]any{"COPY": map[string]any{"operationId": "copyPayment"}},
			},
		},
		"webhooks": map[string]any{"payment": map[string]any{"post": map[string]any{"operationId": "paymentHook"}}},
	}
	report := Analyze(spec)
	if report.Summary.Operations != 2 || report.Summary.Webhooks != 1 {
		t.Fatalf("summary = %#v", report.Summary)
	}
	for _, id := range []string{"AUTH002", "AUTH006", "TLS001", "SURFACE002", "SPEC001"} {
		if !hasFinding(report, id) {
			t.Errorf("missing finding %s: %#v", id, report.Findings)
		}
	}
	if !FailsThreshold(report, SeverityHigh) {
		t.Fatal("high threshold did not fail")
	}
}

func TestAnalyzeDetectsUndefinedSchemeAndPathContract(t *testing.T) {
	spec := map[string]any{
		"openapi":  "3.1.1",
		"security": []any{map[string]any{"missing": []any{}}},
		"paths":    map[string]any{"/users/{id}": map[string]any{"trace": map[string]any{"operationId": "traceUser"}}},
	}
	report := Analyze(spec)
	for _, id := range []string{"AUTH007", "SPEC008", "HTTP001"} {
		if !hasFinding(report, id) {
			t.Errorf("missing finding %s", id)
		}
	}
}

func TestAnalyzeDetectsRootPathAndAdditionalOperationContractErrors(t *testing.T) {
	spec := map[string]any{
		"openapi": "3.2.0",
		"info":    map[string]any{"title": "Broken", "version": "1"},
		"paths": map[string]any{
			"items/{id}": map[string]any{
				"get":                  map[string]any{"parameters": []any{map[string]any{"name": "other", "in": "path", "required": true}}},
				"additionalOperations": map[string]any{"POST": map[string]any{}, "BAD METHOD": map[string]any{}},
			},
			"items/{name}": map[string]any{"get": map[string]any{}},
		},
	}
	report := Analyze(spec)
	for _, id := range []string{"SPEC012", "SPEC013", "SPEC014", "SPEC015", "SPEC016"} {
		if !hasFinding(report, id) {
			t.Errorf("missing finding %s", id)
		}
	}
}

func TestAnalyzeIsDeterministicWithDuplicateOperationIDs(t *testing.T) {
	spec := map[string]any{
		"openapi": "3.1.2", "info": map[string]any{"title": "API", "version": "1"},
		"paths": map[string]any{
			"/z": map[string]any{"get": map[string]any{"operationId": "duplicate"}},
			"/a": map[string]any{"get": map[string]any{"operationId": "duplicate"}},
		},
	}
	want := Analyze(spec)
	for range 20 {
		if got := Analyze(spec); !reflect.DeepEqual(got, want) {
			t.Fatalf("nondeterministic report:\nwant %#v\n got %#v", want, got)
		}
	}
}

func TestAnalyzeMalformedEmptyPathAndMethodDoesNotPanic(t *testing.T) {
	spec := map[string]any{"openapi": "3.2.0", "paths": map[string]any{"": map[string]any{
		"additionalOperations": map[string]any{"": map[string]any{}},
	}}}
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("Analyze panicked: %v", recovered)
		}
	}()
	_ = Analyze(spec)
}

func TestAnalyzeValidatesLegacyAndModernSecuritySchemes(t *testing.T) {
	legacy := Analyze(map[string]any{
		"swagger": "2.0", "info": map[string]any{"title": "Legacy", "version": "1"}, "paths": map[string]any{},
		"securityDefinitions": map[string]any{"oauth": map[string]any{"type": "oauth2", "flow": "implicit"}},
	})
	if !hasFinding(legacy, "AUTH003") {
		t.Fatal("Swagger 2 implicit OAuth flow was not detected")
	}

	modern := Analyze(map[string]any{
		"openapi": "3.2.0", "info": map[string]any{"title": "Modern", "version": "1"}, "paths": map[string]any{},
		"components": map[string]any{"securitySchemes": map[string]any{
			"badKey":  map[string]any{"type": "apiKey", "in": "body"},
			"badHTTP": map[string]any{"type": "http"},
			"unknown": map[string]any{"type": "magic"},
		}},
	})
	for _, id := range []string{"AUTH010", "AUTH011", "AUTH012"} {
		if !hasFinding(modern, id) {
			t.Errorf("missing finding %s", id)
		}
	}
}

func TestAnalyzeValidatesServerURLsAndVariables(t *testing.T) {
	report := Analyze(map[string]any{
		"openapi": "3.2.0", "info": map[string]any{"title": "Servers", "version": "1"}, "paths": map[string]any{},
		"servers": []any{
			map[string]any{"url": "https://{region}.example", "variables": map[string]any{}},
			map[string]any{"url": "https://api.example/v1?secret=value"},
			map[string]any{"url": "http://api.example"},
		},
	})
	for _, id := range []string{"SPEC018", "SPEC019", "TLS001"} {
		if !hasFinding(report, id) {
			t.Errorf("missing finding %s", id)
		}
	}
}

func TestWriteJSONAndSARIF(t *testing.T) {
	report := Analyze(map[string]any{"openapi": "3.1.1", "paths": map[string]any{"/health": map[string]any{"get": map[string]any{}}}})
	for _, format := range []string{"json", "sarif"} {
		var buffer bytes.Buffer
		if err := Write(report, format, &buffer); err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
			t.Fatalf("%s output is invalid JSON: %v", format, err)
		}
	}
}

func TestConsoleOutputEscapesUntrustedControlCharacters(t *testing.T) {
	report := Report{OpenAPIVersion: "3.2.0", Title: "unsafe\x1b[2J", Findings: []Finding{{ID: "TEST", Severity: SeverityHigh, Location: "/path\nforged", Title: "title", Recommendation: "fix"}}}
	var buffer bytes.Buffer
	if err := Write(report, "console", &buffer); err != nil {
		t.Fatal(err)
	}
	if bytes.ContainsAny(buffer.Bytes(), "\x1b\r") || bytes.Count(buffer.Bytes(), []byte("\n")) != 5 {
		t.Fatalf("console output contains injected controls: %q", buffer.String())
	}
}

func hasFinding(report Report, id string) bool {
	for _, finding := range report.Findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}
