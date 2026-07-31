package brute

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestRunTargetContextStopsAfterConsecutiveTransportFailures(t *testing.T) {
	cfg := config.New()
	client := httpclient.NewClient(cfg)
	calls := 0
	client.HTTP.Transport = bruteRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("target unreachable")
	})
	report, err := NewScanner(client, cfg).RunTargetContext(t.Context(), "https://api.example", false)
	if err != nil {
		t.Fatal(err)
	}
	if calls != maxConsecutiveTransportErrors {
		t.Fatalf("transport calls = %d, want %d", calls, maxConsecutiveTransportErrors)
	}
	if report.Summary.Errors != maxConsecutiveTransportErrors || !report.Summary.TransportErrorLimitReached {
		t.Fatalf("summary = %#v", report.Summary)
	}
}

func TestFindAllDefinitionFilesStopsOnAdvertisedRateDepletion(t *testing.T) {
	cfg := config.New()
	client := httpclient.NewClient(cfg)
	calls := 0
	client.HTTP.Transport = bruteRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		header := http.Header{"Content-Type": []string{"application/json"}}
		header.Set("RateLimit-Remaining", "1")
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header:     header,
			Body:       io.NopCloser(strings.NewReader(`{"error":"missing"}`)),
			Request:    request,
		}, nil
	})

	_, _, summary, err := NewScanner(client, cfg).findAllDefinitionFiles(t.Context(), []string{
		"https://api.example.test/one", "https://api.example.test/two",
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !summary.RateLimitReached {
		t.Fatalf("calls=%d summary=%#v", calls, summary)
	}
}

func TestRunTargetContextResetsTransportFailureLimitAfterResponse(t *testing.T) {
	cfg := config.New()
	client := httpclient.NewClient(cfg)
	calls := 0
	client.HTTP.Transport = bruteRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if calls == 3 {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"error":"missing"}`)),
				Request:    request,
			}, nil
		}
		if calls == 6 {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"openapi":"3.1.0","info":{"title":"Found","version":"1"},"paths":{}}`)),
				Request:    request,
			}, nil
		}
		if calls < 6 {
			return nil, errors.New("temporary transport failure")
		}
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"error":"missing"}`)),
			Request:    request,
		}, nil
	})
	report, err := NewScanner(client, cfg).RunTargetContext(t.Context(), "https://api.example", false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.TransportErrorLimitReached {
		t.Fatalf("transport failure limit was not reset: %#v", report.Summary)
	}
	if len(report.SpecsFound) != 1 || calls < 6 {
		t.Fatalf("calls=%d specs=%#v", calls, report.SpecsFound)
	}
}

func TestRunTargetsContextUsesWorkersAndPreservesInputOrder(t *testing.T) {
	cfg := config.New()
	client := httpclient.NewClient(cfg)
	started := make(chan string, 2)
	release := make(chan struct{})
	seen := make(map[string]bool)
	var seenMu sync.Mutex
	client.HTTP.Transport = bruteRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		seenMu.Lock()
		first := !seen[request.URL.Host]
		seen[request.URL.Host] = true
		seenMu.Unlock()
		status := http.StatusNotFound
		body := `{"error":"missing"}`
		if first {
			started <- request.URL.Host
			<-release
			status = http.StatusOK
			body = `{"openapi":"3.1.0","info":{"title":"Concurrent","version":"1"},"paths":{}}`
		}
		return &http.Response{
			StatusCode: status,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    request,
		}, nil
	})

	targets := []string{"https://one.test", "https://two.test"}
	type outcome struct {
		reports []Report
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		reports, err := NewScanner(client, cfg).RunTargetsContext(t.Context(), targets, 2)
		done <- outcome{reports: reports, err: err}
	}()

	for range 2 {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			close(release)
			result := <-done
			t.Fatalf("two targets did not start concurrently: %v", result.err)
		}
	}
	close(release)
	result := <-done
	if result.err != nil {
		t.Fatal(result.err)
	}
	if len(result.reports) != len(targets) {
		t.Fatalf("reports = %d, want %d", len(result.reports), len(targets))
	}
	for index, report := range result.reports {
		if report.Target != targets[index] {
			t.Fatalf("report %d target = %q, want %q", index, report.Target, targets[index])
		}
	}
}

func TestRunTargetsContextPreflightsCompleteBatchBeforeRequests(t *testing.T) {
	cfg := config.New()
	client := httpclient.NewClient(cfg)
	calls := 0
	client.HTTP.Transport = bruteRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("unexpected request")
	})
	_, err := NewScanner(client, cfg).RunTargetsContext(t.Context(), []string{"https://valid.test", "not-a-url"}, 2)
	if err == nil {
		t.Fatal("invalid target batch was accepted")
	}
	if calls != 0 {
		t.Fatalf("sent %d requests before rejecting the complete target batch", calls)
	}
}

func TestRunTargetsContextContainsTargetFailureAndCompletesPeers(t *testing.T) {
	cfg := config.New()
	scanner := NewScanner(httpclient.NewClient(cfg), cfg)
	var scanned []string
	scanner.runTarget = func(_ context.Context, target string, _ bool) (Report, error) {
		scanned = append(scanned, target)
		report := Report{Target: target, SpecsFound: []SpecResult{}, Interesting: []Interesting{}}
		if strings.Contains(target, "bad") {
			return report, errors.New("target-local fixture failure")
		}
		return report, nil
	}
	targets := []string{"https://bad.test", "https://healthy.test"}
	reports, err := scanner.RunTargetsContext(t.Context(), targets, 1)
	var partial *PartialBatchError
	if !errors.As(err, &partial) {
		t.Fatalf("error = %v, want PartialBatchError", err)
	}
	if len(scanned) != 2 || len(reports) != 2 || reports[1].Target != targets[1] {
		t.Fatalf("scanned=%v reports=%#v", scanned, reports)
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

func TestFindAllDefinitionFilesFiltersWildcard200Responses(t *testing.T) {
	cfg := config.New()
	cfg.BruteWorkers = 2
	client := httpclient.NewClient(cfg)
	client.HTTP.Transport = bruteRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
			Body:       io.NopCloser(strings.NewReader("<html><body>application shell</body></html>")),
			Request:    request,
		}, nil
	})
	candidates := []string{
		"https://api.example/a", "https://api.example/b", "https://api.example/c",
		"https://api.example/d", "https://api.example/e", "https://api.example/f",
	}
	_, interesting, summary, err := NewScanner(client, cfg).findAllDefinitionFiles(t.Context(), candidates)
	if err != nil {
		t.Fatal(err)
	}
	if len(interesting) != 0 {
		t.Fatalf("wildcard responses were retained: %#v", interesting)
	}
	if !summary.WildcardResponseDetected || summary.FalsePositivesFiltered != len(candidates) {
		t.Fatalf("summary = %#v", summary)
	}
}

func TestFindAllDefinitionFilesKeepsValidSpecDespiteWildcardResponses(t *testing.T) {
	cfg := config.New()
	cfg.BruteWorkers = 2
	client := httpclient.NewClient(cfg)
	client.HTTP.Transport = bruteRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := "<html><body>application shell</body></html>"
		contentType := "text/html"
		if strings.HasSuffix(request.URL.Path, "/openapi.json") {
			body = `{"openapi":"3.1.0","info":{"title":"Found","version":"1"},"paths":{}}`
			contentType = "application/json"
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{contentType}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    request,
		}, nil
	})
	candidates := []string{
		"https://api.example/a", "https://api.example/b", "https://api.example/c",
		"https://api.example/d", "https://api.example/e", "https://api.example/openapi.json",
	}
	matches, interesting, summary, err := NewScanner(client, cfg).findAllDefinitionFiles(t.Context(), candidates)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].url != candidates[len(candidates)-1] {
		t.Fatalf("matches = %#v", matches)
	}
	if len(interesting) != 0 || summary.FalsePositivesFiltered != summary.URLsTested-1 {
		t.Fatalf("interesting=%#v summary=%#v", interesting, summary)
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
