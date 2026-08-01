package fuzz

import (
	"io"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRunExecutesCapturedWorkflowAndVerifiesPersistedSideEffect(t *testing.T) {
	var created atomic.Bool
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/items":
			created.Store(true)
			return fuzzResponse(request, http.StatusCreated, `{"id":7,"name":"sj-workflow"}`)
		case request.Method == http.MethodGet && request.URL.Path == "/items/7" && created.Load():
			return fuzzResponse(request, http.StatusOK, `{"id":7,"name":"sj-workflow"}`)
		default:
			return fuzzResponse(request, http.StatusNotFound, `{}`)
		}
	})}
	workflow := Workflow{Name: "create-read", Steps: []WorkflowStep{
		{Name: "create", Method: "POST", URL: "https://api.example/items", Body: []byte(`{"name":"sj-workflow"}`), ExpectStatus: []int{201}, Capture: map[string]string{"item_id": "id"}},
		{Name: "verify", Method: "GET", URL: "https://api.example/items/{{item_id}}", ExpectStatus: []int{200}, AssertJSON: map[string]any{"name": "sj-workflow"}, VerifySideEffect: true},
	}}
	report, err := run(t.Context(), client, nil, Options{MaxRequests: 10, Delay: minimumRequestDelay, AcceptRisk: true, Workflows: []Workflow{workflow}}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.SideEffectsVerified != 1 || report.Summary.Requests != 2 {
		t.Fatalf("report = %#v", report)
	}
}

func TestRunDoesNotStartUnsafeWorkflowWithoutAcceptRisk(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		body, _ := io.ReadAll(request.Body)
		return fuzzResponse(request, http.StatusOK, string(body))
	})}
	workflow := Workflow{Name: "unsafe", Steps: []WorkflowStep{{Name: "write", Method: "POST", URL: "https://api.example/items", Body: []byte(`{"name":"test"}`)}}}
	report, err := run(t.Context(), client, nil, Options{MaxRequests: 10, Delay: minimumRequestDelay, Workflows: []Workflow{workflow}}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 || report.Summary.SkippedUnsafe == 0 {
		t.Fatalf("calls=%d report=%#v", calls.Load(), report)
	}
	for _, probe := range report.Probes {
		if strings.EqualFold(probe.Method, "POST") {
			t.Fatalf("unsafe workflow probe was executed: %#v", probe)
		}
	}
}

func TestRunPreflightsEveryWorkflowBeforeNetworkIO(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		return fuzzResponse(request, http.StatusOK, `{}`)
	})}
	workflows := []Workflow{
		{Name: "valid-first", Steps: []WorkflowStep{{Name: "read", Method: "GET", URL: "https://api.example/items"}}},
		{Name: "invalid-later", Steps: []WorkflowStep{{Name: "read", Method: "GET", URL: "https://api.example/items", Identity: "missing"}}},
	}
	_, err := run(t.Context(), client, nil, Options{
		MaxRequests: 10, Delay: minimumRequestDelay, Workflows: workflows,
		Identities: []Identity{{Name: "known", Headers: map[string]string{}}},
	}, noWait)
	if err == nil || !strings.Contains(err.Error(), "unknown identity") {
		t.Fatalf("error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("network calls before complete workflow validation = %d", calls.Load())
	}
}

func TestWorkflowRunIsolatesRateLimitedOriginAndContinuesHealthyOrigin(t *testing.T) {
	var requested []string
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requested = append(requested, request.URL.String())
		if request.URL.Host == "limited.example" {
			return fuzzResponse(request, http.StatusTooManyRequests, `{"error":"limited"}`)
		}
		return fuzzResponse(request, http.StatusOK, `{"ok":true}`)
	})}
	workflows := []Workflow{
		{Name: "limited-first", Steps: []WorkflowStep{
			{Name: "limited", Method: http.MethodGet, URL: "https://limited.example/one"},
			{Name: "limited-skipped", Method: http.MethodGet, URL: "https://limited.example/two"},
		}},
		{Name: "healthy", Steps: []WorkflowStep{
			{Name: "healthy", Method: http.MethodGet, URL: "https://healthy.example/one", ExpectStatus: []int{http.StatusOK}},
		}},
	}
	report, err := run(t.Context(), client, nil, Options{
		MaxRequests: 10, Delay: minimumRequestDelay, Workflows: workflows,
		ContinueOnTargetError: true,
	}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://limited.example/one", "https://healthy.example/one"}
	if !slices.Equal(requested, want) {
		t.Fatalf("requested URLs = %v, want %v", requested, want)
	}
	if report.Summary.RateLimitedOrigins != 1 || report.Summary.SkippedIsolated != 1 {
		t.Fatalf("summary = %#v", report.Summary)
	}
}
