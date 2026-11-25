package brute

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/openapi"
	"github.com/mr-pmillz/sj/pkg/output"
	"github.com/mr-pmillz/sj/pkg/scanner"
)

const probeOperation = `"paths":{"/probe":{"get":{"responses":{"200":{"description":"ok"}}}}}`

// apiBaseDocument is one specification served by the discovery test server
// and the api_base discovery must report for it. "{origin}" stands for the
// test server's own origin; an empty wantAPIBase means the member is omitted
// because the test stage cannot resolve a base for that document.
type apiBaseDocument struct {
	name        string
	path        string
	query       string
	body        string
	wantAPIBase string
}

func apiBaseDocuments() []apiBaseDocument {
	return []apiBaseDocument{
		{
			name: "openapi 3 names a base on another host", path: "/cross/openapi.json",
			body:        `{"openapi":"3.1.0","info":{"title":"Cross","version":"1"},"servers":[{"url":"https://backend.example.net/v3"}],` + probeOperation + `}`,
			wantAPIBase: "https://backend.example.net/v3",
		},
		{
			name: "openapi 3 relative server", path: "/relative/openapi.yaml",
			body:        "openapi: 3.0.3\ninfo:\n  title: Relative\n  version: '1'\nservers:\n  - url: /api/v1/\npaths:\n  /probe:\n    get:\n      responses:\n        '200':\n          description: ok\n",
			wantAPIBase: "{origin}/api/v1",
		},
		{
			name: "openapi 3 server variables with defaults", path: "/variables/openapi.json",
			body: `{"openapi":"3.2.0","info":{"title":"Variables","version":"1"},"servers":[{"url":"https://{region}.example.net/{version}",` +
				`"variables":{"region":{"default":"eu","enum":["eu","us"]},"version":{"default":"v2"}}}],` + probeOperation + `}`,
			wantAPIBase: "https://eu.example.net/v2",
		},
		{
			name: "openapi 3 without servers", path: "/plain/openapi.json",
			body:        `{"openapi":"3.1.0","info":{"title":"Plain","version":"1"},` + probeOperation + `}`,
			wantAPIBase: "{origin}",
		},
		{
			name: "openapi 3 server naming the scheme's default port", path: "/port/openapi.json",
			body:        `{"openapi":"3.1.0","info":{"title":"Port","version":"1"},"servers":[{"url":"https://api.example.net:443/v1"}],` + probeOperation + `}`,
			wantAPIBase: "https://api.example.net/v1",
		},
		{
			name: "openapi 3 server naming another port", path: "/otherport/openapi.json",
			body:        `{"openapi":"3.1.0","info":{"title":"Other port","version":"1"},"servers":[{"url":"http://api.example.net:8080"}],` + probeOperation + `}`,
			wantAPIBase: "http://api.example.net:8080",
		},
		{
			name: "swagger 2 host, schemes and basePath", path: "/hosted/swagger.json",
			body:        `{"swagger":"2.0","info":{"title":"Hosted","version":"1"},"host":"api.example.net:8443","schemes":["https"],"basePath":"/v1",` + probeOperation + `}`,
			wantAPIBase: "https://api.example.net:8443/v1",
		},
		{
			name: "swagger 2 host only takes the document scheme", path: "/hostonly/swagger.json",
			body:        `{"swagger":"2.0","info":{"title":"Host only","version":"1"},"host":"api.example.net",` + probeOperation + `}`,
			wantAPIBase: "http://api.example.net",
		},
		{
			name: "swagger 2 with neither host nor schemes", path: "/neither/swagger.json",
			body:        `{"swagger":"2.0","info":{"title":"Neither","version":"1"},"basePath":"/api",` + probeOperation + `}`,
			wantAPIBase: "{origin}/api",
		},
		{
			name: "server variable without a default cannot be resolved", path: "/unresolved/openapi.json",
			body: `{"openapi":"3.1.0","info":{"title":"Unresolved","version":"1"},"servers":[{"url":"https://{tenant}.example.net",` +
				`"variables":{"tenant":{"description":"no default"}}}],` + probeOperation + `}`,
		},
		{
			name: "document URL with a query and no server cannot be resolved", path: "/queried/openapi.json", query: "format=json",
			body: `{"openapi":"3.1.0","info":{"title":"Queried","version":"1"},` + probeOperation + `}`,
		},
		{
			name: "javascript bundle the test stage unwraps too", path: "/bundle/swagger-ui-init.js",
			body: `window.onload = function () { window.ui = SwaggerUIBundle({"spec": {"openapi":"3.0.3","info":{"title":"Bundled","version":"1"},` +
				`"servers":[{"url":"https://bundled.example.net/api"}],` + probeOperation + `}, "dom_id": "#swagger-ui"}); };`,
			wantAPIBase: "https://bundled.example.net/api",
		},
		{
			// Discovery reports the embedded document's metadata, but the
			// test stage reads the outer document from this JSON URL, so the
			// API base must be the outer document's.
			name: "document embedding another under a spec member", path: "/outer/openapi.json",
			body: `{"openapi":"3.1.0","info":{"title":"Outer","version":"1"},"servers":[{"url":"https://outer.example.net/v1"}],` + probeOperation + `,` +
				`"x-example":{"spec":{"openapi":"3.0.0","info":{"title":"Inner","version":"1"},"servers":[{"url":"https://inner.example.org/v9"}],"paths":{}}}}`,
			wantAPIBase: "https://outer.example.net/v1",
		},
		{
			name: "page embedding a document the test stage cannot read", path: "/page/index.html",
			body: `<html><body><script>const ui = SwaggerUIBundle({"spec": {"openapi":"3.0.3","info":{"title":"Paged","version":"1"},` +
				`"servers":[{"url":"https://paged.example.net"}],` + probeOperation + `}});</script></body></html>`,
		},
	}
}

// TestDiscoveryReportsTheAPIBaseItsTestStageUses serves each document over
// HTTP, finds it through the discovery path, and checks the reported
// api_base against the request URL the test stage plans for the same
// document: discovery and the test stage must name the same API base.
func TestDiscoveryReportsTheAPIBaseItsTestStageUses(t *testing.T) {
	documents := apiBaseDocuments()
	byPath := make(map[string]apiBaseDocument, len(documents))
	for _, document := range documents {
		byPath[document.path] = document
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		document, ok := byPath[request.URL.Path]
		if !ok || request.URL.RawQuery != document.query {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(document.body))
	}))
	t.Cleanup(server.Close)

	var wordlist strings.Builder
	for _, document := range documents {
		line := strings.TrimPrefix(document.path, "/")
		if document.query != "" {
			line += "?" + document.query
		}
		wordlist.WriteString(line + "\n")
	}
	wordlistPath := filepath.Join(t.TempDir(), "wordlist.txt")
	if err := os.WriteFile(wordlistPath, []byte(wordlist.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.EndpointWordlist = wordlistPath
	cfg.BruteOutputFormat = "json"
	cfg.MaxCandidates = 1000
	report, err := NewScanner(httpclient.NewClient(cfg), cfg).RunTargetContext(t.Context(), server.URL, false)
	if err != nil {
		t.Fatalf("discovery failed: %v", err)
	}

	found := make([]string, 0, len(report.SpecsFound))
	for _, spec := range report.SpecsFound {
		found = append(found, spec.URL)
	}
	want := make([]string, 0, len(documents))
	for _, document := range documents {
		want = append(want, documentURL(server.URL, document))
	}
	sort.Strings(found)
	sort.Strings(want)
	if strings.Join(found, "\n") != strings.Join(want, "\n") {
		t.Fatalf("specifications found = %v, want every served document once: %v", found, want)
	}

	for _, spec := range report.SpecsFound {
		parsed, err := url.Parse(spec.URL)
		if err != nil {
			t.Fatal(err)
		}
		document := byPath[parsed.Path]
		t.Run(document.name, func(t *testing.T) {
			wantAPIBase := strings.ReplaceAll(document.wantAPIBase, "{origin}", server.URL)
			if spec.APIBase != wantAPIBase {
				t.Fatalf("api_base = %q, want %q", spec.APIBase, wantAPIBase)
			}
			planned, planErr := testStageProbeURL(spec.URL, []byte(document.body))
			if wantAPIBase == "" {
				if planErr == nil {
					t.Fatalf("api_base is omitted but the test stage plans %q", planned)
				}
				return
			}
			if planErr != nil {
				t.Fatalf("api_base = %q but the test stage refuses the document: %v", spec.APIBase, planErr)
			}
			assertSameEndpoint(t, spec.APIBase+"/probe", planned)
		})
	}
}

func documentURL(origin string, document apiBaseDocument) string {
	if document.query == "" {
		return origin + document.path
	}
	return origin + document.path + "?" + document.query
}

// testStageProbeURL runs the test stage's own pipeline over the bytes the
// document URL serves, with no --target or --base-path (prepare mode, which
// plans every request automate would send and sends none), and returns the
// URL of the document's one operation, GET /probe.
func testStageProbeURL(specURL string, body []byte) (string, error) {
	cfg := config.New()
	cfg.Mode = config.ModePrepare
	cfg.SwaggerURL = specURL
	writer := output.NewWriter(cfg)
	if err := scanner.GenerateRequestsIntoWriterE(body, httpclient.NewClient(cfg), cfg, writer, openapi.NewResolver("")); err != nil {
		return "", err
	}
	if len(writer.PreparedRequests) != 1 {
		return "", fmt.Errorf("planned %d requests, want 1", len(writer.PreparedRequests))
	}
	return writer.PreparedRequests[0].URL, nil
}

// assertSameEndpoint compares two URLs by what a request reaches: scheme,
// host, port (the scheme's default when none is written) and escaped path.
func assertSameEndpoint(t *testing.T, got, want string) {
	t.Helper()
	gotURL, gotErr := url.Parse(got)
	wantURL, wantErr := url.Parse(want)
	if gotErr != nil || wantErr != nil {
		t.Fatalf("parse %q: %v; parse %q: %v", got, gotErr, want, wantErr)
	}
	endpoint := func(value *url.URL) string {
		port := value.Port()
		if port == "" {
			port = map[string]string{"http": "80", "https": "443"}[value.Scheme]
		}
		return value.Scheme + "://" + net.JoinHostPort(value.Hostname(), port) + value.EscapedPath()
	}
	if endpoint(gotURL) != endpoint(wantURL) {
		t.Fatalf("api_base names %q, the test stage sends to %q", got, want)
	}
}

func TestStructuredOutputsCarryTheAPIBase(t *testing.T) {
	reports := []Report{{
		Target: "https://example.com",
		SpecsFound: []SpecResult{
			{URL: "https://example.com/openapi.json", ContentType: "application/json", OpenAPIVersion: "3.1.0", Title: "Resolved", APIBase: "https://api.example.net/v1"},
			{URL: "https://example.com/unresolved.json", ContentType: "application/json", OpenAPIVersion: "3.1.0", Title: "Unresolved"},
		},
		Summary: Summary{URLsTested: 2, SpecsFoundCount: 2},
	}}

	var jsonOutput bytes.Buffer
	if err := WriteJSON(reports, &jsonOutput); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		SpecsFound []map[string]any `json:"specs_found"`
	}
	if err := json.Unmarshal(jsonOutput.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if got := decoded.SpecsFound[0]["api_base"]; got != "https://api.example.net/v1" {
		t.Fatalf("brute.json api_base = %v", got)
	}
	if _, present := decoded.SpecsFound[1]["api_base"]; present {
		t.Fatalf("brute.json names an api_base for an unresolved document: %v", decoded.SpecsFound[1])
	}

	var jsonlOutput bytes.Buffer
	if err := WriteJSONL(reports, &jsonlOutput); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(jsonlOutput.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("brute.jsonl lines = %d, want 2", len(lines))
	}
	for index, want := range []string{"https://api.example.net/v1", ""} {
		var row map[string]any
		if err := json.Unmarshal([]byte(lines[index]), &row); err != nil {
			t.Fatal(err)
		}
		got, present := row["api_base"]
		if want == "" && present || want != "" && got != want {
			t.Fatalf("brute.jsonl line %d api_base = %v (present %v), want %q", index+1, got, present, want)
		}
	}

	var csvOutput bytes.Buffer
	if err := WriteCSV(reports, &csvOutput); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(&csvOutput).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	wantHeader := []string{"target", "url", "content_type", "openapi_version", "title", "description", "api_base"}
	if strings.Join(records[0], ",") != strings.Join(wantHeader, ",") {
		t.Fatalf("brute.csv header = %v, want the earlier columns unchanged and api_base last", records[0])
	}
	if records[1][6] != "https://api.example.net/v1" || records[2][6] != "" {
		t.Fatalf("brute.csv api_base cells = %q and %q", records[1][6], records[2][6])
	}

	var txtOutput bytes.Buffer
	if err := WriteTXT(reports, &txtOutput); err != nil {
		t.Fatal(err)
	}
	if txtOutput.String() != "https://example.com/openapi.json\nhttps://example.com/unresolved.json\n" {
		t.Fatalf("brute.txt must stay one specification URL per line, got %q", txtOutput.String())
	}
}

// TestDiscoveryAPIBaseIgnoresTheRunsTargetAndBasePath pins that a --target
// or --base-path given to the discovery run changes only which candidates
// are probed, never the reported API base: it is the document's own base,
// the one a later test run without those options would use.
func TestDiscoveryAPIBaseIgnoresTheRunsTargetAndBasePath(t *testing.T) {
	documents := map[string]string{
		"/candidates/openapi.json": `{"openapi":"3.1.0","info":{"title":"Elsewhere","version":"1"},"servers":[{"url":"https://backend.example.net/v3"}],` + probeOperation + `}`,
		"/candidates/swagger.json": `{"swagger":"2.0","info":{"title":"Plain","version":"1"},` + probeOperation + `}`,
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, ok := documents[request.URL.Path]
		if !ok {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	wordlistPath := filepath.Join(t.TempDir(), "wordlist.txt")
	if err := os.WriteFile(wordlistPath, []byte("openapi.json\nswagger.json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.EndpointWordlist = wordlistPath
	cfg.BruteOutputFormat = "json"
	cfg.MaxCandidates = 1000
	cfg.BasePath = "/candidates"
	cfg.BasePathExplicit = true
	cfg.APITarget = "https://override.example.org/custom"
	cfg.TargetExplicit = true
	report, err := NewScanner(httpclient.NewClient(cfg), cfg).RunTargetContext(t.Context(), server.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		server.URL + "/candidates/openapi.json": "https://backend.example.net/v3",
		server.URL + "/candidates/swagger.json": server.URL,
	}
	if len(report.SpecsFound) != len(want) {
		t.Fatalf("specs found = %#v", report.SpecsFound)
	}
	for _, spec := range report.SpecsFound {
		if spec.APIBase != want[spec.URL] {
			t.Errorf("%s api_base = %q, want the document's own base %q", spec.URL, spec.APIBase, want[spec.URL])
		}
	}
}
