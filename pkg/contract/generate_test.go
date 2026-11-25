package contract

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
)

const sampleContract = `openapi: 3.0.3
info: {title: Examples, version: "1"}
paths:
  /items/{id}:
    parameters:
      - {name: id, in: path, required: true, schema: {type: string, default: old}}
    get:
      operationId: readFixture
      parameters:
        - name: id
          in: path
          required: true
          schema: {type: string}
          examples: {z: {value: second}, a: {value: first}}
        - name: labels
          in: query
          required: true
          schema: {type: array, items: {type: string}}
          example: [blue, green]
        - {name: X-Region, in: header, required: true, schema: {type: string, enum: [east, west]}}
      responses: {'200': {description: found}}
  /orders:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema: {type: object, required: [quantity], properties: {quantity: {type: integer}}}
            examples: {normal: {value: {quantity: 2}}}
      responses: {'201': {description: created}}
`

func TestGenerateDocumentedExamples(t *testing.T) {
	suite, gaps, err := Generate(t.Context(), []byte(sampleContract), Suite{})
	if err != nil || len(gaps) != 0 || len(suite.Cases) != 2 {
		t.Fatalf("generate: %v, gaps %v", err, gaps)
	}
	first, second := suite.Cases[0], suite.Cases[1]
	if first.Name != "readFixture" || first.PathParams["id"] != "first" || first.Headers["X-Region"] != "east" ||
		first.Query != "labels=blue&labels=green" || first.ExpectStatus != 200 || second.Name != "POST /orders" ||
		second.ExpectStatus != 201 || second.JSONBody != `{"quantity":2}` {
		t.Fatalf("unexpected generated examples: %+v", suite)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/items/first":
			if !slices.Equal(r.URL.Query()["labels"], []string{"blue", "green"}) || r.Header.Get("X-Region") != "east" {
				t.Error("generated query or header did not reach fixture")
			}
		case "/orders":
			w.WriteHeader(http.StatusCreated)
		default:
			t.Error("unexpected fixture path")
		}
	}))
	t.Cleanup(server.Close)
	cfg := config.New()
	cfg.LocalFile, cfg.APITarget, cfg.Force = filepath.Join(t.TempDir(), "api.yaml"), server.URL, true
	if err := os.WriteFile(cfg.LocalFile, []byte(sampleContract), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Run(t.Context(), cfg, suite)
	if err != nil || report.Passed != 2 {
		t.Fatalf("generated suite: %+v, error %v", report, err)
	}
	overrides := Suite{Cases: []Case{{Method: "get", Path: first.Path, Query: "labels=gold", PathParams: map[string]string{"id": "custom"}}}}
	a, _, err := Generate(t.Context(), []byte(sampleContract), overrides)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := Generate(t.Context(), []byte(sampleContract), overrides)
	if err != nil || !reflect.DeepEqual(a, b) || a.Cases[0].PathParams["id"] != "custom" || a.Cases[0].Query != "labels=gold" {
		t.Fatalf("unstable fixture merge: %v", err)
	}
}

func TestGeneratorReportsInputGapsAndFixtureMistakes(t *testing.T) {
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	_, gaps, err := Generate(t.Context(), data, Suite{})
	want := []string{"POST /echo needs request body", "GET /items/{id} needs path parameter id", "GET /items/{id} needs query parameter count"}
	if err != nil || !slices.Equal(gaps, want) {
		t.Fatalf("missing inputs %v, error %v", gaps, err)
	}
	for _, cases := range [][]Case{
		{{Method: "GET", Path: "/absent"}},
		{{Method: "GET", Path: "/me"}, {Method: "get", Path: "/me"}},
	} {
		if _, _, err := Generate(t.Context(), data, Suite{Cases: cases}); err == nil {
			t.Fatal("accepted invalid fixtures")
		}
	}
}

func TestLoopbackFixtureScope(t *testing.T) {
	cfg := config.New()
	cfg.LocalFile = fixture
	c := Case{Name: "fixture", Method: "GET", Path: "/me"}
	for _, target := range []string{"https://fixture.invalid", "https://127.0.0.1"} {
		cfg.APITarget = target
		if u, _ := url.Parse(target); u.Hostname() == "127.0.0.1" {
			cfg.Proxy = "http://proxy.invalid"
		}
		_, err := Run(t.Context(), cfg, Suite{LoopbackOnly: true, Cases: []Case{c}})
		if err == nil || err.Error() != "this fixture suite requires a direct numeric loopback target" {
			t.Fatalf("fixture scope error %v", err)
		}
	}
}
