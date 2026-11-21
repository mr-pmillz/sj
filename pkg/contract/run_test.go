package contract

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
)

const fixture = "../../tests/contract_service.yaml"

func privateFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "headers")
	if err := os.WriteFile(path, []byte(contents+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunCredentialedSuite(t *testing.T) {
	const token = "local-fixture-token"
	const subject = "fixture-caller"
	spec, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /spec", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("credential sent when fetching specification")
		}
		_, _ = w.Write(spec)
	})
	mux.HandleFunc("GET /v1/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Revision", "2")
		_ = json.NewEncoder(w).Encode(map[string]string{"subject": subject, "echo": token})
	})
	mux.HandleFunc("GET /v1/items/7", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.URL.Query().Get("count") != "3" {
			t.Error("incorrect public request")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "3")
	})
	mux.HandleFunc("POST /v1/echo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Authorization") != "" {
			t.Error("incorrect JSON request headers")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.Copy(w, r.Body)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	cfg := config.New()
	cfg.SwaggerURL, cfg.APITarget, cfg.Force = server.URL+"/spec", server.URL+"/v1", true
	cfg.HeaderFile = privateFile(t, "Authorization: Bearer "+token)
	me := Case{Name: "caller", Method: "GET", Path: "/me", Authenticated: true, ExpectJSON: map[string]any{"/subject": subject}}
	item := Case{Name: "count", Method: "GET", Path: "/items/{id}", PathParams: map[string]string{"id": "7"}, Query: "count=3", ExpectJSON: map[string]any{"": 3}}
	echo := Case{Name: "JSON body", Method: "POST", Path: "/echo", JSONBody: `{"subject":"fixture-caller"}`, ExpectStatus: 201, ExpectJSON: me.ExpectJSON}
	repeated := me
	repeated.Name = "caller again"
	report, err := Run(t.Context(), cfg, Suite{[]Case{me, item, echo, repeated}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed != 4 || report.Failed != 0 || report.Coverage != (Coverage{3, 3, 4, 3}) {
		t.Fatalf("unexpected suite report: %+v", report)
	}
	if !report.Cases[0].Credentialed || report.Cases[1].Credentialed || report.Cases[1].MatchedResponse != "2XX" {
		t.Fatalf("incorrect case metadata: %+v", report.Cases)
	}
	b, err := json.Marshal(report)
	if err != nil || strings.Contains(string(b), token) || strings.Contains(string(b), subject) || strings.Contains(string(b), "count=3") {
		t.Fatal("report exposed exchange data or failed to encode")
	}
	cfg.HeaderFile = privateFile(t, "Authorization: Bearer deliberately-rejected-fixture")
	report, err = Run(t.Context(), cfg, Suite{[]Case{me}})
	if err != nil || report.Failed != 1 || report.Cases[0].Status != 401 || report.Cases[0].MatchedResponse != "default" {
		t.Fatalf("rejected credential must fail an affirmative case: %+v, %v", report, err)
	}
}

func TestRunPreflightsEveryCase(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { received.Add(1) }))
	t.Cleanup(server.Close)
	cfg := config.New()
	cfg.LocalFile, cfg.APITarget = fixture, server.URL
	first := Case{Name: "valid", Method: "GET", Path: "/items/{id}", PathParams: map[string]string{"id": "7"}, Query: "count=2"}
	for _, tc := range []struct {
		name string
		last Case
	}{
		{"missing credential", Case{Method: "GET", Path: "/me"}},
		{"no anonymous fallback", Case{Method: "GET", Path: first.Path, PathParams: first.PathParams, Query: first.Query, Authenticated: true}},
		{"guarded method", Case{Method: "POST", Path: "/echo", JSONBody: `{"subject":"test"}`}},
		{"missing parameters", Case{Method: "GET", Path: first.Path}},
		{"invalid path parameter", Case{Method: "GET", Path: first.Path, PathParams: map[string]string{"id": "text"}, Query: first.Query}},
		{"invalid query parameter", Case{Method: "GET", Path: first.Path, PathParams: first.PathParams, Query: "count=text"}},
		{"undefined operation", Case{Method: "GET", Path: "/missing"}},
		{"invalid assertion", Case{Method: "GET", Path: first.Path, PathParams: first.PathParams, Query: first.Query, ExpectJSON: map[string]any{"bad": 1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.last.Name = tc.name
			_, err := Run(t.Context(), cfg, Suite{[]Case{first, tc.last}})
			if err == nil || received.Load() != 0 {
				t.Fatalf("preflight error %v, requests %d", err, received.Load())
			}
		})
	}
	cfg.Force = true
	_, err := Run(t.Context(), cfg, Suite{[]Case{first, {Name: "invalid body", Method: "POST", Path: "/echo", JSONBody: `{"subject":1}`}}})
	if err == nil || received.Load() != 0 {
		t.Fatalf("invalid request body: error %v, requests %d", err, received.Load())
	}
}

func TestRunValidatesCookieExchangeAndConcreteRoute(t *testing.T) {
	const spec = `openapi: 3.0.3
info: {title: Fixture session, version: "1"}
components:
  securitySchemes:
    sid: {type: apiKey, in: cookie, name: sid}
paths:
  /session/current:
    get:
      security: [{sid: []}]
      responses:
        '204':
          description: Session renewed
          headers:
            Set-Cookie: {required: true, schema: {type: string}}
  /session/{name}:
    get:
      parameters: [{in: path, name: name, required: true, schema: {type: string}}]
      responses:
        '204': {description: Known session}
`
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		sid, err := r.Cookie("sid")
		if err != nil || sid.Value != "fixture-session" || r.URL.Path != "/api/session/current" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "renewed-fixture", HttpOnly: true})
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	cfg := config.New()
	cfg.APITarget, cfg.BasePath = server.URL+"/old", "/api"
	cfg.LocalFile = filepath.Join(t.TempDir(), "api.yaml")
	if err := os.WriteFile(cfg.LocalFile, []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.HeaderFile = privateFile(t, "Cookie: sid=fixture-session")
	c := Case{Name: "renew", Method: "get", Path: "/session/current", Authenticated: true, ExpectStatus: 204}
	report, err := Run(t.Context(), cfg, Suite{[]Case{c}})
	if err != nil || report.Passed != 1 || hits.Load() != 1 {
		t.Fatalf("cookie exchange %+v, error %v", report, err)
	}
	c.Path, c.PathParams, c.Authenticated = "/session/{name}", map[string]string{"name": "current"}, false
	if _, err := Run(t.Context(), cfg, Suite{[]Case{c}}); err == nil || hits.Load() != 1 {
		t.Fatalf("ambiguous example reached a different operation, error %v", err)
	}
}

func TestResponseProblems(t *testing.T) {
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := loadDocument(t.Context(), data)
	if err != nil {
		t.Fatal(err)
	}
	ref := doc.Paths.Value("/me").Get.Responses.Value("200")
	for _, tc := range []struct{ name, revision, media, body, issue string }{
		{"valid", "1", "application/json", `{"subject":"fixture"}`, ""},
		{"header missing", "", "application/json", `{"subject":"fixture"}`, "response_header_mismatch"},
		{"header type", "one", "application/json", `{"subject":"fixture"}`, "response_header_mismatch"},
		{"media type", "1", "text/plain", "fixture", "unexpected_content_type"},
		{"invalid JSON", "1", "application/json", "{} {}", "invalid_response_json"},
		{"schema", "1", "application/json", `{"subject":9}`, "response_schema_mismatch"},
		{"empty JSON", "1", "application/json", "", "invalid_response_json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{"Content-Type": {tc.media}}
			if tc.revision != "" {
				headers.Set("X-Revision", tc.revision)
			}
			if got := validateResponse(t.Context(), doc, ref, headers, []byte(tc.body), false); got != tc.issue {
				t.Fatalf("issue %q, want %q", got, tc.issue)
			}
		})
	}
}

func TestScalarAssertions(t *testing.T) {
	fields := map[string]any{"/a~1b/0": nil, "/count": 1, "/large": uint64(9007199254740993), "/missing": nil}
	assertions, err := compileAssertions(fields)
	if err != nil {
		t.Fatal(err)
	}
	failures := checkAssertions([]byte(`{"a/b":[null],"count":1.00,"large":9007199254740992}`), assertions)
	if !reflect.DeepEqual(failures, []string{"assertion_mismatch /large", "assertion_mismatch /missing"}) {
		t.Fatalf("mismatches %v", failures)
	}
}
