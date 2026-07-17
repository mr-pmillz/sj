package brute

import (
	"slices"
	"testing"
)

func TestGeneratePathVariations_VersionSwap(t *testing.T) {
	results := GeneratePathVariations("https://example.com/api/v1/swagger.json")

	expected := []string{
		"https://example.com/api/v2/swagger.json",
		"https://example.com/api/v3/swagger.json",
	}
	for _, want := range expected {
		if !slices.Contains(results, want) {
			t.Errorf("expected %q in variations, got: %v", want, results)
		}
	}

	if slices.Contains(results, "https://example.com/api/v1/swagger.json") {
		t.Error("should not include the original URL in variations")
	}
}

func TestGeneratePathVariations_ExtensionSwap(t *testing.T) {
	results := GeneratePathVariations("https://example.com/swagger.json")

	expected := []string{
		"https://example.com/swagger.yaml",
		"https://example.com/swagger.yml",
	}
	for _, want := range expected {
		if !slices.Contains(results, want) {
			t.Errorf("expected %q in variations, got: %v", want, results)
		}
	}
}

func TestGeneratePathVariations_YAMLToJSON(t *testing.T) {
	results := GeneratePathVariations("https://example.com/openapi.yaml")

	if !slices.Contains(results, "https://example.com/openapi.json") {
		t.Errorf("expected .json variant, got: %v", results)
	}
}

func TestGeneratePathVariations_SiblingPaths(t *testing.T) {
	results := GeneratePathVariations("https://example.com/api/swagger.json")

	if !slices.Contains(results, "https://example.com/api/openapi.json") {
		t.Errorf("expected sibling openapi.json, got: %v", results)
	}
	if !slices.Contains(results, "https://example.com/api/api-docs") {
		t.Errorf("expected sibling api-docs, got: %v", results)
	}
}

func TestGeneratePathVariations_CombinedVersionAndExtension(t *testing.T) {
	results := GeneratePathVariations("https://example.com/v2/swagger.json")

	if !slices.Contains(results, "https://example.com/v1/swagger.json") {
		t.Errorf("expected v1 version swap, got: %v", results)
	}
	if !slices.Contains(results, "https://example.com/v2/swagger.yaml") {
		t.Errorf("expected yaml extension swap, got: %v", results)
	}
}

func TestGeneratePathVariations_NoDuplicates(t *testing.T) {
	results := GeneratePathVariations("https://example.com/api/v1/swagger.json")

	seen := map[string]bool{}
	for _, r := range results {
		if seen[r] {
			t.Errorf("duplicate variation: %s", r)
		}
		seen[r] = true
	}
}

func TestGeneratePathVariations_InvalidURL(t *testing.T) {
	results := GeneratePathVariations("://not-a-url")

	if results != nil {
		t.Errorf("expected nil for invalid URL, got: %v", results)
	}
}
