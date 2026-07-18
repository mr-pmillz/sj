package fuzz

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/apitest"
	pentestreport "github.com/mr-pmillz/sj/pkg/report"
)

type fuzzRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn fuzzRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func fuzzResponse(request *http.Request, status int, body string) (*http.Response, error) {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
}

func TestRunStopsImmediatelyOnRateLimit(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		return fuzzResponse(request, http.StatusTooManyRequests, `{"error":"slow down"}`)
	})}
	operations := []pentestreport.Operation{
		{Method: "GET", URL: "https://api.example/a", Target: "/a"},
		{Method: "GET", URL: "https://api.example/b", Target: "/b"},
	}
	report, err := run(t.Context(), client, operations, Options{MaxRequests: 20, Delay: minimumRequestDelay}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || report.Summary.Requests != 1 || !report.Summary.RateLimited {
		t.Fatalf("calls=%d report=%#v", calls.Load(), report)
	}
}

func TestRunStopsBeforeConsumingLastAdvertisedRateLimitRequest(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		response, err := fuzzResponse(request, http.StatusOK, `{}`)
		response.Header.Set("RateLimit-Remaining", "1")
		return response, err
	})}
	operations := []pentestreport.Operation{
		{Method: "GET", URL: "https://api.example/a", Target: "/a"},
		{Method: "GET", URL: "https://api.example/b", Target: "/b"},
	}
	report, err := run(t.Context(), client, operations, Options{MaxRequests: 20, Delay: minimumRequestDelay}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || !report.Summary.RateLimited || report.Probes[0].RateLimitRemaining == nil || *report.Probes[0].RateLimitRemaining != 1 {
		t.Fatalf("calls=%d report=%#v", calls.Load(), report)
	}
}

func TestRunSkipsStateChangingOperationsWithoutAcceptRisk(t *testing.T) {
	var methods []string
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		methods = append(methods, request.Method)
		return fuzzResponse(request, http.StatusOK, `{}`)
	})}
	operations := []pentestreport.Operation{
		{Method: "POST", URL: "https://api.example/items", Target: "/items", RequestBody: `{}`},
		{Method: "GET", URL: "https://api.example/health", Target: "/health"},
	}
	report, err := run(t.Context(), client, operations, Options{MaxRequests: 20, Delay: minimumRequestDelay}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	if len(methods) == 0 || strings.Contains(strings.Join(methods, ","), "POST") || report.Summary.SkippedUnsafe == 0 {
		t.Fatalf("methods=%v summary=%#v", methods, report.Summary)
	}
}

func TestRunRejectsOversizedBaselineBeforeNetworkIO(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		return fuzzResponse(request, http.StatusOK, `{}`)
	})}
	operation := pentestreport.Operation{Method: "GET", URL: "https://api.example/search", Target: "/search", RequestBody: strings.Repeat("x", apitest.MaximumPayloadBytes+1)}
	_, err := run(t.Context(), client, []pentestreport.Operation{operation}, Options{MaxRequests: 10, Delay: minimumRequestDelay}, noWait)
	if err == nil || calls.Load() != 0 {
		t.Fatalf("error=%v calls=%d", err, calls.Load())
	}
}

func TestRunFindsPIIAndVerboseErrorsWithoutCopyingMatchedData(t *testing.T) {
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return fuzzResponse(request, http.StatusInternalServerError, `{"email":"private-person@example.test","error":"stack trace /home/service/main.go:10"}`)
	})}
	report, err := run(t.Context(), client, []pentestreport.Operation{{Method: "GET", URL: "https://api.example/users/1", Target: "/users/1"}}, Options{MaxRequests: 10, Delay: minimumRequestDelay}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	joined := ""
	for _, finding := range report.Findings {
		joined += finding.Category + " " + finding.Evidence + "\n"
	}
	if !strings.Contains(joined, "pii_exposure") || !strings.Contains(joined, "verbose_error") {
		t.Fatalf("findings = %#v", report.Findings)
	}
	if strings.Contains(joined, "private-person") {
		t.Fatalf("raw PII leaked into findings: %s", joined)
	}
}

func TestRunComparesIdentitiesAndUsernameEnumeration(t *testing.T) {
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/users/10" {
			if request.Header.Get("Authorization") == "Bearer identity-b" {
				return fuzzResponse(request, http.StatusForbidden, `{"error":"forbidden"}`)
			}
			return fuzzResponse(request, http.StatusOK, `{"id":10}`)
		}
		body, _ := io.ReadAll(request.Body)
		if strings.Contains(string(body), "sj-nonexistent") {
			return fuzzResponse(request, http.StatusNotFound, `{"error":"unknown user"}`)
		}
		return fuzzResponse(request, http.StatusUnauthorized, `{"error":"bad password"}`)
	})}
	operations := []pentestreport.Operation{
		{Method: "GET", URL: "https://api.example/users/10", Target: "/users/10"},
		{Method: "POST", URL: "https://api.example/login", Target: "/login", ContentType: "application/json", RequestBody: `{"username":"alice","password":"invalid"}`},
	}
	report, err := run(t.Context(), client, operations, Options{
		MaxRequests: 100, Delay: minimumRequestDelay, AcceptRisk: true, KnownUsername: "alice",
		Identities: []Identity{
			{Name: "identity-a", Headers: map[string]string{"Authorization": "Bearer identity-a"}},
			{Name: "identity-b", Headers: map[string]string{"Authorization": "Bearer identity-b"}},
		},
	}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	categories := ""
	for _, finding := range report.Findings {
		categories += finding.Category + "\n"
	}
	if !strings.Contains(categories, "identity_access_difference") || !strings.Contains(categories, "username_enumeration") {
		t.Fatalf("findings = %#v", report.Findings)
	}
}

func TestRunComparesUsernameEnumerationAcrossMutatedQueryURLs(t *testing.T) {
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Query().Get("username") == "sj-nonexistent-7f3a1d" {
			return fuzzResponse(request, http.StatusNotFound, `{"error":"unknown user"}`)
		}
		return fuzzResponse(request, http.StatusUnauthorized, `{"error":"bad password"}`)
	})}
	operation := pentestreport.Operation{
		Method: "GET", URL: "https://api.example/recover?username=alice", Target: "/recover", Status: http.StatusOK,
	}
	report, err := run(t.Context(), client, []pentestreport.Operation{operation}, Options{
		MaxRequests: 20, Delay: minimumRequestDelay, KnownUsername: "alice",
	}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range report.Findings {
		if finding.Category == "username_enumeration" {
			return
		}
	}
	t.Fatalf("query-based username enumeration finding missing: %#v", report.Findings)
}

func noWait(_ context.Context, _ time.Duration) error { return nil }
