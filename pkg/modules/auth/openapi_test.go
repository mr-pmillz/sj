package auth

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestAnalyzeOpenAPIReportsCoverageAndSchemeContextWithoutSecrets(t *testing.T) {
	const secretExample = "do-not-leak-this-api-key"
	spec := []byte(`
openapi: 3.1.0
security:
  - bearerAuth: []
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
    apiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
    oauth:
      type: oauth2
      flows:
        authorizationCode:
          authorizationUrl: https://identity.example.invalid/authorize
          tokenUrl: https://identity.example.invalid/token
          scopes: {read: Read access}
    oidc:
      type: openIdConnect
      openIdConnectUrl: https://identity.example.invalid/.well-known/openid-configuration
paths:
  /secure:
    get:
      responses: {'200': {description: ok}}
  /anonymous:
    get:
      security: []
      x-example-secret: ` + secretExample + `
      responses: {'200': {description: ok}}
  /undefined:
    get:
      security:
        - missingScheme: []
      responses: {'200': {description: ok}}
`)

	report, err := AnalyzeOpenAPI(spec, OpenAPIOptions{})
	if err != nil {
		t.Fatalf("AnalyzeOpenAPI() error = %v", err)
	}
	codes := findingCodes(report.Findings)
	for _, code := range []string{
		"openapi-api-key-context", "openapi-pkce-not-declared",
		"openapi-oidc-discovery-context", "openapi-anonymous-operation",
		"openapi-undefined-security-scheme",
	} {
		if _, found := codes[code]; !found {
			t.Errorf("missing finding %q; got %v", code, codes)
		}
	}
	for _, code := range []string{"openapi-api-key-context", "openapi-pkce-not-declared", "openapi-oidc-discovery-context"} {
		finding := codes[code]
		if finding.Status != StatusCandidate || finding.Context == "" {
			t.Fatalf("finding %q lacks explicit candidate context: %#v", code, finding)
		}
	}
	serialized, _ := json.Marshal(report)
	if strings.Contains(string(serialized), secretExample) || strings.Contains(string(serialized), "identity.example.invalid") {
		t.Fatalf("report leaked spec values: %s", serialized)
	}
}

func TestAnalyzeOpenAPIPKCEExtensionAvoidsFalsePositive(t *testing.T) {
	spec := []byte(`
openapi: 3.0.3
components:
  securitySchemes:
    oauth:
      type: oauth2
      flows:
        authorizationCode:
          x-pkce-required: true
          authorizationUrl: https://identity.example.invalid/authorize
          tokenUrl: https://identity.example.invalid/token
          scopes: {}
paths: {}
`)
	report, err := AnalyzeOpenAPI(spec, OpenAPIOptions{})
	if err != nil {
		t.Fatalf("AnalyzeOpenAPI() error = %v", err)
	}
	if _, found := findingCodes(report.Findings)["openapi-pkce-not-declared"]; found {
		t.Fatalf("PKCE extension was ignored: %#v", report.Findings)
	}
}

func TestAnalyzeSwaggerOAuthAndQueryAPIKeyPosture(t *testing.T) {
	spec := []byte(`
swagger: '2.0'
securityDefinitions:
  legacyOAuth:
    type: oauth2
    flow: implicit
    authorizationUrl: https://identity.example.invalid/authorize
    scopes: {}
  queryKey:
    type: apiKey
    in: query
    name: key
security:
  - legacyOAuth: []
paths: {}
`)
	report, err := AnalyzeOpenAPI(spec, OpenAPIOptions{})
	if err != nil {
		t.Fatalf("AnalyzeOpenAPI() error = %v", err)
	}
	codes := findingCodes(report.Findings)
	for _, code := range []string{"openapi-oauth-legacy-flow", "openapi-api-key-query"} {
		if _, found := codes[code]; !found {
			t.Fatalf("missing Swagger posture finding %q: %#v", code, report.Findings)
		}
	}
}

func TestAnalyzeOpenAPIEnforcesDocumentBoundsAndRejectsAliases(t *testing.T) {
	tests := []struct {
		name      string
		spec      []byte
		options   OpenAPIOptions
		wantError error
	}{
		{name: "bytes", spec: []byte(strings.Repeat("x", 65)), options: OpenAPIOptions{Limits: SpecLimits{MaxBytes: 64}}, wantError: ErrSpecTooLarge},
		{name: "depth", spec: []byte("openapi: 3.0.0\na: {b: {c: {d: value}}}\npaths: {}\n"), options: OpenAPIOptions{Limits: SpecLimits{MaxDepth: 3}}, wantError: ErrSpecStructureLimit},
		{name: "aliases", spec: []byte("openapi: 3.0.0\nvalue: &shared {secret: hidden}\ncopy: *shared\npaths: {}\n"), options: OpenAPIOptions{}, wantError: ErrSpecUnsafeSyntax},
		{name: "duplicate mapping key", spec: []byte("openapi: 3.0.0\nsecurity: []\nsecurity: [{bearer: []}]\npaths: {}\n"), options: OpenAPIOptions{}, wantError: ErrSpecUnsafeSyntax},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := AnalyzeOpenAPI(test.spec, test.options)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("AnalyzeOpenAPI() error = %v, want %v", err, test.wantError)
			}
		})
	}
}

func TestAnalyzeOpenAPIAggregatesRepeatedCoverageSignals(t *testing.T) {
	paths := make(map[string]any)
	for index := 0; index < 100; index++ {
		paths["/public/"+strings.Repeat("x", index%8)+string(rune('a'+index%26))] = map[string]any{
			"get": map[string]any{"security": []any{}, "responses": map[string]any{}},
		}
	}
	spec, err := json.Marshal(map[string]any{"openapi": "3.0.3", "paths": paths})
	if err != nil {
		t.Fatal(err)
	}
	report, err := AnalyzeOpenAPI(spec, OpenAPIOptions{})
	if err != nil {
		t.Fatalf("AnalyzeOpenAPI() error = %v", err)
	}
	count := 0
	for _, finding := range report.Findings {
		if finding.Code == "openapi-anonymous-operation" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("anonymous-operation findings = %d, want one aggregated candidate", count)
	}
}
