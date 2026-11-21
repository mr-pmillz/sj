package contract

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/mr-pmillz/sj/pkg/privateheaders"
)

func TestConfigureAuth(t *testing.T) {
	const target = "https://fixture.example"
	headerFile := privateFile(t, "Authorization: Basic Zml4dHVyZTpxYQ==\nCookie: sid=fixture\nX-Key: fixture")
	policy, err := privateheaders.Load(headerFile, []string{target}, nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := &openapi3.T{
		Components: &openapi3.Components{SecuritySchemes: openapi3.SecuritySchemes{
			"key":    {Value: &openapi3.SecurityScheme{Type: "apiKey", In: "header", Name: "X-Key"}},
			"cookie": {Value: &openapi3.SecurityScheme{Type: "apiKey", In: "cookie", Name: "sid"}},
			"basic":  {Value: &openapi3.SecurityScheme{Type: "http", Scheme: "basic"}},
			"oauth":  {Value: &openapi3.SecurityScheme{Type: "oauth2"}},
		}},
		Security: openapi3.SecurityRequirements{{"key": {}, "cookie": {}}},
	}
	optional := openapi3.SecurityRequirements{{}, {"basic": {}}}
	public := openapi3.SecurityRequirements{}
	all := openapi3.SecurityRequirements{{"basic": {}, "oauth": {"read"}}}
	choice := openapi3.SecurityRequirements{{"oauth": {"read"}}, {"basic": {}}}
	for _, tc := range []struct {
		name         string
		requirements *openapi3.SecurityRequirements
		requireAuth  bool
		otherOrigin  bool
		credentialed bool
		wantErr      bool
	}{
		{"global AND", nil, false, false, true, false},
		{"optional anonymous", &optional, false, false, false, false},
		{"optional credential", &optional, true, false, true, false},
		{"operation public", &public, false, false, false, false},
		{"public cannot verify auth", &public, true, false, false, true},
		{"incomplete AND", &all, false, false, false, true},
		{"satisfiable alternative", &choice, true, false, true, false},
		{"different origin", nil, true, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origin := target
			if tc.otherOrigin {
				origin = "https://other.example"
			}
			req := httptest.NewRequest(http.MethodGet, origin+"/me", nil)
			got, err := configureAuth(req, doc, &openapi3.Operation{Security: tc.requirements}, policy, tc.requireAuth)
			if (err != nil) != tc.wantErr || got != tc.credentialed {
				t.Fatalf("credentialed %t, error %v", got, err)
			}
			if !got && req.Header.Get("X-Key") != "" {
				t.Fatal("unused profile was applied")
			}
		})
	}
}
