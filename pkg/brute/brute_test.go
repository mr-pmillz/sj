package brute

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
)

type bruteRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn bruteRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestNormalizeTargetValidatesSchemeAndPreservesPath(t *testing.T) {
	target, base, err := normalizeTarget("https://api.example/docs/", "")
	if err != nil {
		t.Fatal(err)
	}
	if target != "https://api.example" || base != "/docs" {
		t.Fatalf("target = %q base = %q", target, base)
	}
	for _, invalid := range []string{"api.example", "file:///tmp/spec", "https://user:pass@api.example"} {
		if _, _, err := normalizeTarget(invalid, ""); err == nil {
			t.Errorf("accepted invalid target %q", invalid)
		}
	}
}

func TestCandidatesAreDeduplicatedAndBounded(t *testing.T) {
	cfg := config.New()
	scanner := NewScanner(httpclient.NewClient(cfg), cfg)
	candidates, err := scanner.candidates("https://api.example", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != len(deduplicateStrings(candidates)) {
		t.Fatal("candidate list contains duplicates")
	}
	cfg.MaxCandidates = 1
	if _, err := scanner.candidates("https://api.example", ""); err == nil {
		t.Fatal("candidate limit was not enforced")
	}
}

func TestRunTargetContextHonorsCancellationBeforeNetworkIO(t *testing.T) {
	cfg := config.New()
	scanner := NewScanner(httpclient.NewClient(cfg), cfg)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := scanner.RunTargetContext(ctx, "https://api.example", false)
	if err == nil {
		t.Fatal("canceled scan returned no error")
	}
	if report.Summary.URLsTested != 0 {
		t.Fatalf("canceled scan tested %d URLs", report.Summary.URLsTested)
	}
}

func TestCountStatusTracksServerErrorsSeparately(t *testing.T) {
	var summary Summary
	for _, status := range []int{200, 302, 404, 503} {
		countStatus(&summary, status)
	}
	if summary.Responses2xx != 1 || summary.Responses3xx != 1 || summary.Responses4xx != 1 || summary.Responses5xx != 1 {
		t.Fatalf("summary = %#v", summary)
	}
}

func TestBruteDetectsMislabeledOpenAPISpec(t *testing.T) {
	cfg := config.New()
	client := httpclient.NewClient(cfg)
	client.HTTP.Transport = bruteRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := `{"openapi":"3.2.0","info":{"title":"Mislabeled","version":"1"},"webhooks":{}}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/html"}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    request,
		}, nil
	})
	scanner := NewScanner(client, cfg)
	state := &scanState{tested: map[string]bool{}, found: map[string]bool{}}
	scanner.processURL(context.Background(), "https://api.example/openapi", state)
	if len(state.matches) != 1 || state.matches[0].version != "3.2.0" {
		t.Fatalf("matches = %#v, want mislabeled OpenAPI 3.2 document", state.matches)
	}
	if len(state.interesting) != 0 {
		t.Fatalf("valid spec was also recorded as interesting: %#v", state.interesting)
	}
}

func TestTryParseAsSpecRecognizesSwagger2YAMLSchemaTypes(t *testing.T) {
	body, err := os.ReadFile("../../tests/test_spec_v2.yaml")
	if err != nil {
		t.Fatal(err)
	}
	document, version := TryParseAsSpec(body)
	if document == nil || version != "2.0" {
		t.Fatalf("document=%#v version=%q", document, version)
	}
}
