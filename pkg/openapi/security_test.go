package openapi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
)

func TestResolverDisablesExternalFilesWithoutLocalBase(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "secret.yaml")
	if err := os.WriteFile(outside, []byte("type: string\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := NewResolver("").ResolveExternalRef(outside, ""); got != nil {
		t.Fatalf("remote resolver read local file: %#v", got)
	}
}

func TestResolverConfinesExternalRefsToBaseDirectory(t *testing.T) {
	parent := t.TempDir()
	base := filepath.Join(parent, "specs")
	if err := os.Mkdir(base, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "secret.yaml")
	if err := os.WriteFile(outside, []byte("type: string\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := NewResolver(base).ResolveExternalRef("../secret.yaml", base); got != nil {
		t.Fatalf("resolver escaped base directory: %#v", got)
	}
}

func TestResolverDecodesJSONPointerEscapesAndRoot(t *testing.T) {
	spec := map[string]any{"components": map[string]any{"schemas": map[string]any{"a/b~c": map[string]any{"type": "string"}}}}
	resolver := NewResolver("")

	got := resolver.ResolveRef(spec, "#/components/schemas/a~1b~0c")
	if got == nil || got["type"] != "string" {
		t.Fatalf("escaped pointer resolved to %#v", got)
	}
	if root := resolver.ResolveRef(spec, "#"); root == nil {
		t.Fatal("root JSON pointer resolved to nil")
	}
}

func TestExpandSchemaAllowsRepeatedSiblingReferences(t *testing.T) {
	spec := map[string]any{
		"components": map[string]any{"schemas": map[string]any{"Name": map[string]any{"type": "string"}}},
	}
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"first":  map[string]any{"$ref": "#/components/schemas/Name"},
			"second": map[string]any{"$ref": "#/components/schemas/Name"},
		},
	}

	expanded := ExpandSchema(spec, schema, map[string]bool{}, spec, NewResolver(""))
	for _, name := range []string{"first", "second"} {
		if expanded.Properties[name] == nil || expanded.Properties[name].Type != "string" {
			t.Errorf("property %s = %#v, want string schema", name, expanded.Properties[name])
		}
	}
	if got := GenerateExample(expanded, config.New()).(map[string]any); got["first"] != "testvalue" || got["second"] != "testvalue" {
		t.Fatalf("generated repeated refs = %#v", got)
	}
}

func TestExtractJSONFromJSSpecHandlesNestedObjects(t *testing.T) {
	js := []byte(`const ui = {"spec":{"openapi":"3.0.3","info":{"title":"Nested"},"paths":{"/pets":{"get":{"responses":{"200":{"description":"ok"}}}}}}};`)
	got, ok := ExtractJSONFromJSSpec(js)
	if !ok || !LooksLikeAPISpec(got) {
		t.Fatalf("nested JS spec was not extracted: ok=%v body=%q", ok, got)
	}
}

func TestExtractJSONFromSwaggerUIBundleProperty(t *testing.T) {
	js := []byte(`window.ui = SwaggerUIBundle({spec: {"openapi":"3.2.0","info":{"title":"Embedded","version":"1"},"paths":{}}});`)
	got, ok := ExtractJSONFromJSSpec(js)
	if !ok || !LooksLikeAPISpec(got) {
		t.Fatalf("SwaggerUIBundle spec was not extracted: ok=%v body=%q", ok, got)
	}
}

func TestExtractSpecFromJSMalformedInputDoesNotPanic(t *testing.T) {
	malformed := []byte(`window.spec = {"openapi":"3.0.0"`)
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("malformed JS panicked: %v", recovered)
		}
	}()
	if got := ExtractSpecFromJS(malformed); string(got) != string(malformed) {
		t.Fatalf("malformed input changed to %q", got)
	}
}

func TestGenerateExampleSupportsOpenAPI31JSONSchemaKeywords(t *testing.T) {
	schema := map[string]any{
		"type": []any{"object", "null"},
		"properties": map[string]any{
			"kind":       map[string]any{"type": "string", "const": "fixed"},
			"createdAt":  map[string]any{"type": "string", "format": "date-time"},
			"serverOnly": map[string]any{"type": "string", "readOnly": true},
		},
	}
	node := ExpandSchema(schema, schema, map[string]bool{}, schema, NewResolver(""))
	example := GenerateExample(node, config.New()).(map[string]any)
	if example["kind"] != "fixed" || example["createdAt"] != "1990-01-01T00:00:00Z" {
		t.Fatalf("3.1 example = %#v", example)
	}
	if _, exists := example["serverOnly"]; exists {
		t.Fatalf("readOnly request property was generated: %#v", example)
	}
}

func TestExpandSchemaMergesAllOfWithInlineProperties(t *testing.T) {
	spec := map[string]any{"components": map[string]any{"schemas": map[string]any{
		"Base": map[string]any{"type": "object", "properties": map[string]any{"base": map[string]any{"type": "string"}}},
	}}}
	schema := map[string]any{
		"type":       "object",
		"properties": map[string]any{"inline": map[string]any{"type": "boolean"}},
		"allOf":      []any{map[string]any{"$ref": "#/components/schemas/Base"}},
	}
	node := ExpandSchema(spec, schema, map[string]bool{}, spec, NewResolver(""))
	if node.Properties["base"] == nil || node.Properties["inline"] == nil {
		t.Fatalf("allOf properties were not merged: %#v", node.Properties)
	}
}

func TestResolverRejectsSymlinkEscapeAndOversizedExternalFile(t *testing.T) {
	parent := t.TempDir()
	base := filepath.Join(parent, "specs")
	if err := os.Mkdir(base, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "outside.yaml")
	if err := os.WriteFile(outside, []byte("type: string\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link.yaml")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	resolver := NewResolver(base)
	if got := resolver.ResolveExternalRef("link.yaml", base); got != nil {
		t.Fatalf("resolver followed escaping symlink: %#v", got)
	}
	large := filepath.Join(base, "large.yaml")
	file, err := os.Create(large)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxExternalSpecBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if got := resolver.ResolveExternalRef("large.yaml", base); got != nil {
		t.Fatalf("resolver accepted oversized file: %#v", got)
	}
}

func TestResolverTraversesJSONPointerArrays(t *testing.T) {
	spec := map[string]any{"items": []any{map[string]any{"type": "integer"}}}
	got := NewResolver("").ResolveRef(spec, "#/items/0")
	if got == nil || got["type"] != "integer" {
		t.Fatalf("array pointer = %#v", got)
	}
}

func FuzzExtractJSONFromJSSpecDoesNotPanic(f *testing.F) {
	f.Add([]byte(`const spec = {"openapi":"3.2.0","paths":{}};`))
	f.Add([]byte(`window.spec = {"openapi":"3.0.0"`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ExtractJSONFromJSSpec(data)
		_ = ExtractSpecFromJS(data)
	})
}

func FuzzSafelyUnmarshalSpecDoesNotPanic(f *testing.F) {
	f.Add([]byte("openapi: 3.1.1\npaths: {}\n"))
	f.Add([]byte("[not, a, document]"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = SafelyUnmarshalSpec(data)
	})
}

func TestSafelyUnmarshalSpecRejectsNonObjectAndDuplicateKeys(t *testing.T) {
	for _, data := range [][]byte{
		[]byte("null\n"),
		[]byte("openapi: 3.0.0\nopenapi: 3.1.0\n"),
	} {
		if _, err := SafelyUnmarshalSpec(data); err == nil {
			t.Fatalf("accepted invalid document %q", data)
		}
	}
}

func TestValidateReferencePolicyRejectsSSRFAndRemoteLocalReads(t *testing.T) {
	for _, ref := range []string{"http://169.254.169.254/latest/meta-data", "../../etc/passwd"} {
		document := map[string]any{"schema": map[string]any{"$ref": ref}}
		if err := ValidateReferencePolicy(document, NewResolver("")); err == nil {
			t.Errorf("reference %q was accepted for remote document", ref)
		}
	}
	local := t.TempDir()
	if err := ValidateReferencePolicy(map[string]any{"schema": map[string]any{"$ref": "schema.yaml#/Thing"}}, NewResolver(local)); err != nil {
		t.Fatalf("confined local reference was rejected: %v", err)
	}
}

func TestValidateReferencePolicyBoundsNestingDepth(t *testing.T) {
	document := map[string]any{}
	current := document
	for range maxReferencePolicyDepth + 1 {
		next := map[string]any{}
		current["nested"] = next
		current = next
	}
	if err := ValidateReferencePolicy(document, NewResolver("")); err == nil {
		t.Fatal("excessively nested document was accepted")
	}
}
