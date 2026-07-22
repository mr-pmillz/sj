package brute

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
)

func TestBruteFollowsSwaggerUIInitializerAndConfigChain(t *testing.T) {
	cfg := config.New()
	cfg.BruteWorkers = 2
	client := httpclient.NewClient(cfg)
	var calls []string
	client.HTTP.Transport = bruteRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls = append(calls, request.URL.Path)
		status, contentType, body := http.StatusNotFound, "application/json", `{"error":"missing"}`
		switch request.URL.Path {
		case "/docs/index.html":
			status, contentType = http.StatusOK, "text/html"
			body = `<script src="/swagger-ui-bundle.js"></script><script src="/swagger-initializer.js"></script>`
		case "/swagger-initializer.js":
			status, contentType = http.StatusOK, "application/javascript"
			body = `window.ui = SwaggerUIBundle({configUrl: "/swagger-config"})`
		case "/swagger-config":
			status, contentType = http.StatusOK, "application/json"
			body = `{"urls":[{"name":"v1","url":"/opaque-v1"},{"name":"v2","url":"/opaque-v2"}]}`
		case "/opaque-v1":
			status, contentType = http.StatusOK, "application/json"
			body = `{"openapi":"3.1.0","info":{"title":"V1","version":"1"},"paths":{}}`
		case "/opaque-v2":
			status, contentType = http.StatusOK, "application/json"
			body = `{"openapi":"3.1.0","info":{"title":"V2","version":"2"},"paths":{}}`
		}
		return bruteResponse(request, status, contentType, body), nil
	})

	matches, _, _, err := NewScanner(client, cfg).findAllDefinitionFiles(t.Context(), []string{"https://api.example/docs/index.html"})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 {
		t.Fatalf("matches = %#v, want both configured specifications", matches)
	}
	wantPrefix := []string{"/docs/index.html", "/swagger-initializer.js", "/swagger-config", "/opaque-v1", "/opaque-v2"}
	if len(calls) < len(wantPrefix) || !slices.Equal(calls[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("request order = %v, want prefix %v", calls, wantPrefix)
	}
	if slices.Contains(calls, "/swagger-ui-bundle.js") {
		t.Fatalf("library bundle was followed as an initializer: %v", calls)
	}
}

func TestDiscoveredReferenceIsPromotedAheadOfBulkCandidates(t *testing.T) {
	cfg := config.New()
	cfg.BruteWorkers = 2
	client := httpclient.NewClient(cfg)
	var calls []string
	client.HTTP.Transport = bruteRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls = append(calls, request.URL.Path)
		switch request.URL.Path {
		case "/docs":
			return bruteResponse(request, http.StatusOK, "text/html", `<script>SwaggerUIBundle({url: "/openapi.json"})</script>`), nil
		case "/openapi.json":
			return bruteResponse(request, http.StatusOK, "application/json", `{"openapi":"3.1.0","info":{"title":"Promoted","version":"1"},"paths":{}}`), nil
		default:
			return bruteResponse(request, http.StatusNotFound, "application/json", `{"error":"missing"}`), nil
		}
	})

	candidates := []string{"https://api.example/docs", "https://api.example/decoy", "https://api.example/openapi.json"}
	matches, _, _, err := NewScanner(client, cfg).findAllDefinitionFiles(t.Context(), candidates)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("matches = %#v", matches)
	}
	if len(calls) < 2 || calls[0] != "/docs" || calls[1] != "/openapi.json" {
		t.Fatalf("discovered reference was not promoted: %v", calls)
	}
}

func TestDiscoveryReferencePolicyNeverRequestsCrossOriginTargets(t *testing.T) {
	cfg := config.New()
	cfg.BruteWorkers = 2
	cfg.Headers = []string{"Authorization: Bearer assessment-secret"}
	client := httpclient.NewClient(cfg)
	var calls []string
	client.HTTP.Transport = bruteRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls = append(calls, request.URL.String())
		if request.URL.Host != "api.example" {
			t.Fatalf("cross-origin reference was requested with authorization %q: %s", request.Header.Get("Authorization"), request.URL)
		}
		switch request.URL.Path {
		case "/docs":
			return bruteResponse(request, http.StatusOK, "text/html", `<script src="/swagger-initializer.js"></script>`), nil
		case "/swagger-initializer.js":
			return bruteResponse(request, http.StatusOK, "application/javascript", `SwaggerUIBundle({configUrl: "/swagger-config"})`), nil
		case "/swagger-config":
			return bruteResponse(request, http.StatusOK, "application/json", `{"urls":[{"url":"https://evil.example/openapi.json"},{"url":"https://user:pass@api.example/private.json"},{"url":"file:///tmp/spec.json"},{"url":"/openapi.json"}]}`), nil
		case "/openapi.json":
			return bruteResponse(request, http.StatusOK, "application/json", `{"openapi":"3.1.0","info":{"title":"Allowed","version":"1"},"paths":{}}`), nil
		default:
			return bruteResponse(request, http.StatusNotFound, "application/json", `{"error":"missing"}`), nil
		}
	})

	matches, _, _, err := NewScanner(client, cfg).findAllDefinitionFiles(t.Context(), []string{"https://api.example/docs"})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].url != "https://api.example/openapi.json" {
		t.Fatalf("matches = %#v, calls = %v", matches, calls)
	}
	for _, call := range calls {
		if strings.Contains(call, "evil.example") || strings.Contains(call, "user:pass") || strings.HasPrefix(call, "file:") {
			t.Fatalf("unsafe reference was requested: %v", calls)
		}
	}
}

func TestDiscoveryReferenceDepthIsBounded(t *testing.T) {
	cfg := config.New()
	cfg.BruteWorkers = 2
	client := httpclient.NewClient(cfg)
	var calls []string
	client.HTTP.Transport = bruteRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls = append(calls, request.URL.Path)
		var level int
		if _, err := fmt.Sscanf(request.URL.Path, "/openapi-level-%d.json", &level); err != nil {
			return bruteResponse(request, http.StatusNotFound, "application/json", `{}`), nil
		}
		if level == 4 {
			return bruteResponse(request, http.StatusOK, "application/json", `{"openapi":"3.1.0","info":{"title":"Too Deep","version":"1"},"paths":{}}`), nil
		}
		body := fmt.Sprintf(`<script>SwaggerUIBundle({url: "/openapi-level-%d.json"})</script>`, level+1)
		return bruteResponse(request, http.StatusOK, "text/html", body), nil
	})

	matches, _, _, err := NewScanner(client, cfg).findAllDefinitionFiles(t.Context(), []string{"https://api.example/openapi-level-0.json"})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("over-depth specification was fetched: %#v", matches)
	}
	if slices.Contains(calls, "/openapi-level-4.json") {
		t.Fatalf("over-depth reference was requested: %v", calls)
	}
}

func TestDiscoveryReferenceFanoutIsBoundedPerResponse(t *testing.T) {
	cfg := config.New()
	cfg.BruteWorkers = 2
	client := httpclient.NewClient(cfg)
	requests := 0
	client.HTTP.Transport = bruteRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.URL.Path != "/docs" {
			return bruteResponse(request, http.StatusNotFound, "application/json", `{}`), nil
		}
		var body strings.Builder
		body.WriteString(`<script>SwaggerUIBundle({urls:[`)
		for index := range 40 {
			if index > 0 {
				body.WriteByte(',')
			}
			fmt.Fprintf(&body, `{url:"/spec-%02d.json"}`, index)
		}
		body.WriteString(`]})</script>`)
		return bruteResponse(request, http.StatusOK, "text/html", body.String()), nil
	})

	_, _, summary, err := NewScanner(client, cfg).findAllDefinitionFiles(t.Context(), []string{"https://api.example/docs"})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 33 {
		t.Fatalf("requests = %d, want root plus 32 followed references", requests)
	}
	if summary.ReferencesSkipped != 8 {
		t.Fatalf("references skipped = %d, want 8", summary.ReferencesSkipped)
	}
}

func TestExtractSpecURLsFromHTMLIncludesEverySwashbuckleDiscoveryPath(t *testing.T) {
	body := []byte(`discoveryPaths: arrayFrom('v1/swagger.json|v2/swagger.json|/v3/api-docs')`)
	got := ExtractSpecURLsFromHTML(body, "https://api.example/docs/index.html")
	want := []string{
		"https://api.example/v1/swagger.json",
		"https://api.example/v2/swagger.json",
		"https://api.example/v3/api-docs",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("discovery paths = %v, want %v", got, want)
	}
}

func TestFindAllDefinitionFilesClassifiesWAFChallenge(t *testing.T) {
	cfg := config.New()
	cfg.BruteWorkers = 2
	client := httpclient.NewClient(cfg)
	client.HTTP.Transport = bruteRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := `<!doctype html><title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script>`
		return bruteResponse(request, http.StatusForbidden, "text/html", body), nil
	})

	_, interesting, summary, err := NewScanner(client, cfg).findAllDefinitionFiles(context.Background(), []string{"https://api.example/openapi.json"})
	if err != nil {
		t.Fatal(err)
	}
	if len(interesting) != 0 {
		t.Fatalf("WAF challenge was recorded as interesting: %#v", interesting)
	}
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["waf_challenge_detected"] != true || fields["waf_challenge_responses"] != float64(1) {
		t.Fatalf("summary did not classify WAF challenge: %s", data)
	}
}

func TestPriorityURLsIncludeSelectedHTMLUIEntrypoints(t *testing.T) {
	for _, entrypoint := range []string{"/docs/index.html", "/swagger/index.html", "/api-docs/index.html", "/redoc/index.html"} {
		if !slices.Contains(PriorityURLs, entrypoint) {
			t.Errorf("priority URLs omit %s", entrypoint)
		}
	}
}

func TestSwaggerUILibraryResponseDoesNotProduceDiscoveryReferences(t *testing.T) {
	body := []byte(`/* swagger-ui bundle */ const defaults = {url: "/openapi.json"}`)
	references := extractDiscoveryReferences(body, "application/javascript", "https://api.example/swagger-ui-bundle.js")
	if len(references.URLs) != 0 {
		t.Fatalf("library bundle produced discovery references: %v", references.URLs)
	}
}

func TestWAFMarkersInsideValidSpecificationAreNotMisclassified(t *testing.T) {
	cfg := config.New()
	cfg.BruteWorkers = 2
	client := httpclient.NewClient(cfg)
	client.HTTP.Transport = bruteRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := `{"openapi":"3.1.0","info":{"title":"Challenge API","version":"1","description":"Documents /cdn-cgi/challenge-platform callbacks"},"paths":{}}`
		return bruteResponse(request, http.StatusOK, "application/json", body), nil
	})

	matches, _, summary, err := NewScanner(client, cfg).findAllDefinitionFiles(t.Context(), []string{"https://api.example/openapi.json"})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 || summary.WAFChallengeDetected {
		t.Fatalf("valid specification was misclassified: matches=%#v summary=%#v", matches, summary)
	}
}

func FuzzExtractDiscoveryReferencesPreservesRequestPolicy(f *testing.F) {
	f.Add([]byte(`<script src="/swagger-initializer.js"></script>`), "text/html")
	f.Add([]byte(`{"urls":[{"url":"/openapi.json"}]}`), "application/json")
	f.Add([]byte(`SwaggerUIBundle({url: "https://evil.example/openapi.json"})`), "application/javascript")
	f.Fuzz(func(t *testing.T, body []byte, contentType string) {
		references := extractDiscoveryReferences(body, contentType, "https://api.example/docs/index.html")
		if len(references.URLs) > maxReferencesPerResponse {
			t.Fatalf("extracted %d references, limit is %d", len(references.URLs), maxReferencesPerResponse)
		}
		for _, raw := range references.URLs {
			parsed, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("invalid extracted URL %q: %v", raw, err)
			}
			if parsed.Scheme != "https" || parsed.Host != "api.example" || parsed.User != nil || parsed.Fragment != "" {
				t.Fatalf("extracted URL escaped request policy: %q", raw)
			}
		}
	})
}

func bruteResponse(request *http.Request, status int, contentType, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{contentType}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}
