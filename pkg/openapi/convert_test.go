package openapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteConvertedFileTruncatesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openapi.json")
	if err := os.WriteFile(path, []byte(`{"long":"stale trailing content"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := WriteConvertedFile([]byte(`{}`), path); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{}` {
		t.Fatalf("converted file = %q, want exact replacement", got)
	}
}

func TestConvertToOpenAPI3ConvertsSwaggerAndSupportsYAML(t *testing.T) {
	swagger := []byte(`swagger: "2.0"
info:
  title: Example
  version: "1.0"
paths:
  /health:
    get:
      responses:
        "200":
          description: ok
`)
	converted, already, err := ConvertToOpenAPI3(swagger, "json")
	if err != nil {
		t.Fatal(err)
	}
	if already || !json.Valid(converted) {
		t.Fatalf("already=%v output=%q", already, converted)
	}
	var document map[string]any
	if err := json.Unmarshal(converted, &document); err != nil {
		t.Fatal(err)
	}
	if version, _ := document["openapi"].(string); version == "" {
		t.Fatalf("converted document = %#v", document)
	}
	if yamlOutput, _, err := ConvertToOpenAPI3(swagger, "yaml"); err != nil || len(yamlOutput) == 0 {
		t.Fatalf("yaml conversion output=%q err=%v", yamlOutput, err)
	}
}

func TestConvertToOpenAPI3RejectsInvalidDocumentsAndFormats(t *testing.T) {
	if _, _, err := ConvertToOpenAPI3([]byte(`{"hello":"world"}`), "json"); err == nil {
		t.Fatal("non-OpenAPI document was accepted")
	}
	if _, _, err := ConvertToOpenAPI3([]byte(`{"openapi":"3.1.1","info":{},"paths":{}}`), "toml"); err == nil {
		t.Fatal("unsupported output format was accepted")
	}
}

func TestConvertToOpenAPI3HandlesRepositorySwagger2SchemaTypes(t *testing.T) {
	body, err := os.ReadFile("../../tests/test_spec_v2.yaml")
	if err != nil {
		t.Fatal(err)
	}
	converted, already, err := ConvertToOpenAPI3(body, "yaml")
	if err != nil {
		t.Fatal(err)
	}
	if already || len(converted) == 0 {
		t.Fatalf("already=%v output=%q", already, converted)
	}
}
