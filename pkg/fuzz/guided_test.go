package fuzz

import (
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mr-pmillz/sj/pkg/apitest"
	pentestreport "github.com/mr-pmillz/sj/pkg/report"
)

func TestGuidedRetryCombinesStructuredValidationRequirements(t *testing.T) {
	plan := plannedProbe{
		method: http.MethodPost, targetURL: "https://api.example/items?lng=testvalue",
		baselineURL: "https://api.example/items?lng=testvalue", body: []byte(`{"names":[{}]}`),
		contentType: "application/json", caseName: "baseline", category: "baseline",
		identity: Identity{Name: "anonymous"},
	}
	response := ProbeResult{Status: http.StatusUnprocessableEntity}
	body := []byte(`{"detail":[
		{"type":"missing","loc":["body","names",0,"prospectId"],"msg":"Field required"},
		{"type":"string_pattern_mismatch","loc":["query","lng"],"msg":"String should match pattern","ctx":{"pattern":"^(es|en)$"}}
	]}`)

	retry, decision := guidedRetry(plan, response, body)
	if !decision.Hinted || !decision.RepairAvailable || decision.Unresolved {
		t.Fatalf("decision = %#v", decision)
	}
	if retry.category != "response_guided" || retry.targetURL != "https://api.example/items?lng=es" {
		t.Fatalf("retry = %#v", retry)
	}
	if !strings.Contains(string(retry.body), `"prospectId":1`) {
		t.Fatalf("body = %s", retry.body)
	}
}

func TestGuidedRetryUnderstandsASPNetAndGoTypeErrors(t *testing.T) {
	testCases := []struct {
		name     string
		plan     plannedProbe
		response string
		wantBody string
		wantURL  string
	}{
		{
			name:     "ASP.NET nested Guid",
			plan:     plannedProbe{method: http.MethodPost, targetURL: "https://api.example/prospects", body: []byte(`{"names":[{"prospectId":"testvalue"}]}`)},
			response: `{"errors":{"$.names[0].prospectId":["The JSON value could not be converted to System.Guid."]}}`,
			wantBody: `"prospectId":"00000000-0000-4000-8000-000000000001"`,
		},
		{
			name:     "Go integer field",
			plan:     plannedProbe{method: http.MethodPost, targetURL: "https://api.example/items", body: []byte(`{"amount":"testvalue"}`)},
			response: `{"error":"json: cannot unmarshal string into Go struct field Request.amount of type int64"}`,
			wantBody: `"amount":1`,
		},
		{
			name:     "strconv query placeholder",
			plan:     plannedProbe{method: http.MethodGet, targetURL: "https://api.example/items?id=testvalue"},
			response: `{"error":"strconv.ParseInt: parsing \"testvalue\": invalid syntax"}`,
			wantURL:  "https://api.example/items?id=1",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			retry, decision := guidedRetry(testCase.plan, ProbeResult{Status: http.StatusBadRequest}, []byte(testCase.response))
			if !decision.RepairAvailable {
				t.Fatalf("decision = %#v", decision)
			}
			if testCase.wantBody != "" && !strings.Contains(string(retry.body), testCase.wantBody) {
				t.Fatalf("body = %s", retry.body)
			}
			if testCase.wantURL != "" && retry.targetURL != testCase.wantURL {
				t.Fatalf("URL = %s", retry.targetURL)
			}
		})
	}
}

func TestGuidedRetryDoesNotInventCredentialsOrGuessAtNoneType(t *testing.T) {
	testCases := []string{
		`{"detail":"Unauthorized. Missing Bearer token or required header: X-Forwarded-Email"}`,
		`{"ok":false,"info":"the JSON object must be str, bytes or bytearray, not NoneType"}`,
		`{"detail":[{"type":"missing","loc":["body","file"],"msg":"Field required"}]}`,
	}
	for _, response := range testCases {
		_, decision := guidedRetry(
			plannedProbe{method: http.MethodPost, targetURL: "https://api.example/auth/password", body: []byte(`{"CodeLogin":"S"}`)},
			ProbeResult{Status: http.StatusBadRequest}, []byte(response),
		)
		if !decision.Hinted || decision.RepairAvailable || !decision.Unresolved {
			t.Fatalf("response=%s decision=%#v", response, decision)
		}
	}
}

func TestRunExecutesBoundedResponseGuidedRetryAndRecordsSuccess(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		if request.URL.Query().Has("sj_probe") {
			return fuzzResponse(request, http.StatusOK, `{"status":"ordinary mutation"}`)
		}
		if request.URL.Query().Get("tenantId") == "1" {
			return fuzzResponse(request, http.StatusOK, `{"id":1,"name":"tenant"}`)
		}
		return fuzzResponse(request, http.StatusUnprocessableEntity, `{"detail":[{"type":"missing","loc":["query","tenantId"],"msg":"Field required"}]}`)
	})}
	report, err := run(t.Context(), client, []pentestreport.Operation{{
		Method: http.MethodGet, URL: "https://api.example/tenants", Target: "/tenants",
	}}, Options{MaxRequests: 10, Delay: minimumRequestDelay, ResponseGuided: true, MaxGuidedRetries: 1}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 || report.Summary.GuidedRetries != 1 || report.Summary.GuidedSuccesses != 1 {
		t.Fatalf("calls=%d summary=%#v probes=%#v", calls.Load(), report.Summary, report.Probes)
	}
	for _, finding := range report.Findings {
		if finding.Category == "response_guided_success" {
			return
		}
	}
	t.Fatalf("guided success finding missing: %#v", report.Findings)
}

func TestRunDoesNotSendGuidedRetryAfterRateLimitSignal(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		response, err := fuzzResponse(request, http.StatusBadRequest, `{"detail":[{"type":"missing","loc":["query","tenantId"],"msg":"Field required"}]}`)
		response.Header.Set("RateLimit-Remaining", "1")
		return response, err
	})}
	report, err := run(t.Context(), client, []pentestreport.Operation{{
		Method: http.MethodGet, URL: "https://api.example/tenants", Target: "/tenants",
	}}, Options{MaxRequests: 10, Delay: minimumRequestDelay, ResponseGuided: true, MaxGuidedRetries: 2}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || report.Summary.GuidedRetries != 0 || !report.Summary.RateLimited {
		t.Fatalf("calls=%d summary=%#v", calls.Load(), report.Summary)
	}
}

func TestRunChainsNewValidationRequirementsOnlyToConfiguredDepth(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		if request.URL.Query().Has("sj_probe") {
			return fuzzResponse(request, http.StatusOK, `{"status":"ordinary mutation"}`)
		}
		if request.URL.Query().Get("tenantId") == "1" && request.URL.Query().Get("lng") == "es" {
			return fuzzResponse(request, http.StatusOK, `{"id":1,"name":"tenant"}`)
		}
		if request.URL.Query().Get("tenantId") == "1" {
			return fuzzResponse(request, http.StatusUnprocessableEntity, `{"detail":[{"type":"string_pattern_mismatch","loc":["query","lng"],"msg":"String should match pattern","ctx":{"pattern":"^(es|en)$"}}]}`)
		}
		return fuzzResponse(request, http.StatusUnprocessableEntity, `{"detail":[{"type":"missing","loc":["query","tenantId"],"msg":"Field required"}]}`)
	})}
	report, err := run(t.Context(), client, []pentestreport.Operation{{
		Method: http.MethodGet, URL: "https://api.example/tenants", Target: "/tenants",
	}}, Options{MaxRequests: 10, Delay: minimumRequestDelay, ResponseGuided: true, MaxGuidedRetries: 2}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 4 || report.Summary.GuidedRetries != 2 || report.Summary.GuidedSuccesses != 1 {
		t.Fatalf("calls=%d summary=%#v probes=%#v", calls.Load(), report.Summary, report.Probes)
	}
}

func TestGuidedRetryRejectsComplexServerSuppliedRegex(t *testing.T) {
	_, decision := guidedRetry(
		plannedProbe{method: http.MethodGet, targetURL: "https://api.example/search?q=testvalue"},
		ProbeResult{Status: http.StatusBadRequest},
		[]byte(`{"detail":[{"type":"string_pattern_mismatch","loc":["query","q"],"msg":"String should match pattern","ctx":{"pattern":"^(a+)+$"}}]}`),
	)
	if !decision.Hinted || decision.RepairAvailable || !decision.Unresolved {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestInjectedReservedEmailIsNotReportedAsExposedPII(t *testing.T) {
	probe := ProbeResult{
		Method: http.MethodPost, URL: "https://api.example/recover", Category: "response_guided",
		analysisBody: []byte(`{"email":"sj-test@example.invalid","accepted":true}`),
	}
	probe.PIITypes = detectPIITypes(probe.analysisBody)
	for _, finding := range AnalyzeProbes([]ProbeResult{probe}) {
		if finding.Category == "pii_exposure" {
			t.Fatalf("scanner-injected reserved email produced a PII finding: %#v", finding)
		}
	}
}

func TestGuidedRepairDoesNotReleasePrecomputedIDORCasesFromInvalidBaseline(t *testing.T) {
	var idorCases atomic.Int32
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		testCase := request.Header.Get("X-SJ-Test-Case")
		if strings.HasPrefix(testCase, "idor_") || strings.HasPrefix(testCase, "idor_range:") {
			idorCases.Add(1)
		}
		if request.URL.Query().Get("tenantId") == "1" || request.URL.Query().Has("sj_probe") {
			return fuzzResponse(request, http.StatusOK, `{"id":10,"owner":"authorized"}`)
		}
		return fuzzResponse(request, http.StatusUnprocessableEntity, `{"detail":[{"type":"missing","loc":["query","tenantId"],"msg":"Field required"}]}`)
	})}
	idRange := apitest.NumericRange{Start: 1, End: 3}
	report, err := run(t.Context(), client, []pentestreport.Operation{{
		Method: http.MethodGet, Status: http.StatusOK, URL: "https://api.example/users/10", Target: "/users/10",
	}}, Options{
		MaxRequests: 30, Delay: minimumRequestDelay, MaxCasesPerOperation: 8, IDORRange: &idRange,
		ResponseGuided: true, MaxGuidedRetries: 2,
	}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	if idorCases.Load() != 0 || report.Summary.RejectedIDORBaselines != 1 || report.Summary.SkippedInvalidIDOR == 0 {
		t.Fatalf("repaired but originally invalid baseline released numeric cases: count=%d summary=%#v", idorCases.Load(), report.Summary)
	}
}

func TestPlanReservesEveryPossibleGuidedRetryBeforeTraffic(t *testing.T) {
	plan, err := Plan([]pentestreport.Operation{{
		Method: http.MethodGet, URL: "https://api.example/tenants", Target: "/tenants",
	}}, Options{MaxRequests: 5, Delay: minimumRequestDelay, ResponseGuided: true, MaxGuidedRetries: 2})
	if err != nil {
		t.Fatal(err)
	}
	if plan.DeterministicRequests != 2 || plan.ReservedGuidedRequests != 4 || plan.RequiredRequests != 6 || !plan.ExceedsBudget {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestGuidedRetryPreservesCompleteRequestBody(t *testing.T) {
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), `"amount":1`) {
			if !strings.Contains(string(body), `"unchanged":"keep"`) {
				t.Fatalf("guided request lost captured fields: %s", body)
			}
			return fuzzResponse(request, http.StatusOK, `{"accepted":true}`)
		}
		return fuzzResponse(request, http.StatusBadRequest, `{"error":"json: cannot unmarshal string into Go struct field Request.amount of type int64"}`)
	})}
	report, err := run(t.Context(), client, []pentestreport.Operation{{
		Method: http.MethodPost, URL: "https://api.example/items", Target: "/items", RequestBody: `{"amount":"testvalue","unchanged":"keep"}`,
	}}, Options{MaxRequests: 20, Delay: minimumRequestDelay, AcceptRisk: true, ResponseGuided: true, MaxGuidedRetries: 1}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.GuidedRetries == 0 {
		t.Fatalf("summary = %#v", report.Summary)
	}
}
