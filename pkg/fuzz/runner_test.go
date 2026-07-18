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
		{Method: "POST", URL: "https://api.example/items", Target: "/items", RequestBody: strings.Repeat("x", apitest.MaximumPayloadBytes+1)},
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

func TestRunPreservesCapturedBaselineAboveMutationLimit(t *testing.T) {
	var calls atomic.Int32
	body := strings.Repeat("x", apitest.MaximumPayloadBytes+1)
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		captured, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(captured) != body {
			t.Fatal("captured baseline body was not preserved")
		}
		return fuzzResponse(request, http.StatusOK, `{}`)
	})}
	operation := pentestreport.Operation{Method: "GET", URL: "https://api.example/search", Target: "/search", RequestBody: body}
	report, err := run(t.Context(), client, []pentestreport.Operation{operation}, Options{MaxRequests: 10, Delay: minimumRequestDelay}, noWait)
	if err != nil || calls.Load() != 1 || report.Summary.Requests != 1 {
		t.Fatalf("error=%v calls=%d report=%#v", err, calls.Load(), report)
	}
}

func TestRunRejectsCapturedBaselineAboveSafeReplayCeiling(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		return fuzzResponse(request, http.StatusOK, `{}`)
	})}
	operation := pentestreport.Operation{
		Method: "GET", URL: "https://api.example/import", Target: "/import",
		RequestBody: strings.Repeat("x", maximumBaselineRequestBytes+1),
	}
	_, err := run(t.Context(), client, []pentestreport.Operation{operation}, Options{MaxRequests: 10, Delay: minimumRequestDelay}, noWait)
	if err == nil || !strings.Contains(err.Error(), "safe replay ceiling") || calls.Load() != 0 {
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

func TestRunFindsDifferentialNumericIDOREnumeration(t *testing.T) {
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		identifier := strings.TrimPrefix(request.URL.Path, "/users/")
		return fuzzResponse(request, http.StatusOK, `{"id":"`+identifier+`","owner":"different"}`)
	})}
	idRange := apitest.NumericRange{Start: 1, End: 3}
	operation := pentestreport.Operation{
		Method: "GET", Status: http.StatusOK, URL: "https://api.example/users/testvalue", Target: "/users/testvalue",
	}
	report, err := run(t.Context(), client, []pentestreport.Operation{operation}, Options{
		MaxRequests: 20, Delay: minimumRequestDelay, MaxCasesPerOperation: 8, IDORRange: &idRange,
	}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range report.Findings {
		if finding.Category == "idor_enumeration" && finding.URL == operation.URL && strings.Contains(finding.Evidence, "successful_object_responses=3") {
			return
		}
	}
	t.Fatalf("numeric IDOR differential finding missing: %#v", report.Findings)
}

func TestRunDoesNotReportIdenticalCatchAllResponsesAsIDOR(t *testing.T) {
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return fuzzResponse(request, http.StatusOK, `{"message":"same catch-all response"}`)
	})}
	idRange := apitest.NumericRange{Start: 1, End: 3}
	operation := pentestreport.Operation{
		Method: "GET", Status: http.StatusOK, URL: "https://api.example/users/testvalue", Target: "/users/testvalue",
	}
	report, err := run(t.Context(), client, []pentestreport.Operation{operation}, Options{
		MaxRequests: 20, Delay: minimumRequestDelay, MaxCasesPerOperation: 8, IDORRange: &idRange,
	}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range report.Findings {
		if finding.Category == "idor_enumeration" {
			t.Fatalf("identical catch-all responses produced a false IDOR finding: %#v", report.Findings)
		}
	}
}

func TestRunDoesNotReportEchoedIDOrFailureEnvelopeAsIDOR(t *testing.T) {
	testCases := []struct {
		name string
		body func(string) string
	}{
		{
			name: "explicit failure envelope",
			body: func(identifier string) string {
				return `{"ok":false,"info":"object ` + identifier + ` not found","data":{}}`
			},
		},
		{
			name: "single changing identifier",
			body: func(identifier string) string {
				return `{"externalId":` + identifier + `}`
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				identifier := strings.TrimPrefix(request.URL.Path, "/users/")
				return fuzzResponse(request, http.StatusOK, testCase.body(identifier))
			})}
			idRange := apitest.NumericRange{Start: 1, End: 3}
			operation := pentestreport.Operation{
				Method: "GET", Status: http.StatusOK, URL: "https://api.example/users/testvalue", Target: "/users/testvalue",
			}
			report, err := run(t.Context(), client, []pentestreport.Operation{operation}, Options{
				MaxRequests: 20, Delay: minimumRequestDelay, MaxCasesPerOperation: 8, IDORRange: &idRange,
			}, noWait)
			if err != nil {
				t.Fatal(err)
			}
			for _, finding := range report.Findings {
				if finding.Category == "idor_enumeration" {
					t.Fatalf("echo/error response produced a false IDOR finding: %#v", report.Findings)
				}
			}
		})
	}
}

func TestRunReportsIncompleteRequestBudget(t *testing.T) {
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return fuzzResponse(request, http.StatusOK, `{}`)
	})}
	idRange := apitest.NumericRange{Start: 1, End: 3}
	report, err := run(t.Context(), client, []pentestreport.Operation{{
		Method: "GET", Status: http.StatusOK, URL: "https://api.example/users/1", Target: "/users/1",
	}}, Options{MaxRequests: 2, Delay: minimumRequestDelay, MaxCasesPerOperation: 8, IDORRange: &idRange}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Summary.RequestBudgetHit || report.Summary.Requests != 1 || report.Summary.SkippedInvalidIDOR != 1 {
		t.Fatalf("request budget was not surfaced: %#v", report.Summary)
	}
}

func TestRunHonorsRequestBudgetAtAndAboveBoundary(t *testing.T) {
	t.Run("exact budget is complete", func(t *testing.T) {
		var calls atomic.Int32
		client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls.Add(1)
			return fuzzResponse(request, http.StatusOK, `{"status":"complete"}`)
		})}
		report, err := run(t.Context(), client, []pentestreport.Operation{{
			Method: http.MethodGet, URL: "https://api.example/search", Target: "/search",
			RequestBody: strings.Repeat("x", apitest.MaximumPayloadBytes+1),
		}}, Options{MaxRequests: 1, Delay: minimumRequestDelay}, noWait)
		if err != nil {
			t.Fatal(err)
		}
		if calls.Load() != 1 || report.Summary.Requests != 1 || report.Summary.RequestBudgetHit {
			t.Fatalf("calls=%d summary=%#v", calls.Load(), report.Summary)
		}
	})

	t.Run("exceeded budget never sends beyond limit", func(t *testing.T) {
		var calls atomic.Int32
		client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls.Add(1)
			return fuzzResponse(request, http.StatusOK, `{"status":"complete"}`)
		})}
		report, err := run(t.Context(), client, []pentestreport.Operation{
			{Method: http.MethodGet, URL: "https://api.example/a", Target: "/a"},
			{Method: http.MethodGet, URL: "https://api.example/b", Target: "/b"},
		}, Options{MaxRequests: 3, Delay: minimumRequestDelay}, noWait)
		if err != nil {
			t.Fatal(err)
		}
		if calls.Load() != 3 || report.Summary.Requests != 3 || !report.Summary.RequestBudgetHit {
			t.Fatalf("calls=%d summary=%#v", calls.Load(), report.Summary)
		}
	})
}

func TestPlanReportsRequiredRequestsBeforeNetworkExecution(t *testing.T) {
	idRange := apitest.NumericRange{Start: 1, End: 3}
	operations := []pentestreport.Operation{
		{Method: "GET", Status: http.StatusOK, URL: "https://api.example/users/1", Target: "/users/1"},
		{Method: "POST", Status: http.StatusCreated, URL: "https://api.example/users/1", Target: "/users/1"},
	}
	plan, err := Plan(operations, Options{
		MaxRequests: 2, Delay: minimumRequestDelay, MaxCasesPerOperation: 8, IDORRange: &idRange,
		Identities: []Identity{{Name: "alice"}, {Name: "bob"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ExceedsBudget || plan.RequiredRequests <= 2 || plan.SkippedUnsafe != 1 {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestRunSkipsNumericIDORCasesWhenLiveBaselineIsFailureEnvelope(t *testing.T) {
	var cases []string
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		cases = append(cases, request.Header.Get("X-SJ-Test-Case"))
		return fuzzResponse(request, http.StatusOK, `{"ok":false,"info":"invalid request","data":{"id":10}}`)
	})}
	idRange := apitest.NumericRange{Start: 1, End: 3}
	report, err := run(t.Context(), client, []pentestreport.Operation{{
		Method: http.MethodGet, Status: http.StatusOK, URL: "https://api.example/users/10", Target: "/users/10",
	}}, Options{MaxRequests: 20, Delay: minimumRequestDelay, MaxCasesPerOperation: 8, IDORRange: &idRange}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range cases {
		if strings.HasPrefix(testCase, "idor_") || strings.HasPrefix(testCase, "idor_range:") {
			t.Fatalf("numeric IDOR case ran after invalid baseline: cases=%v summary=%#v", cases, report.Summary)
		}
	}
	if report.Summary.RejectedIDORBaselines != 1 || report.Summary.QualifiedIDORBaselines != 0 || report.Summary.SkippedInvalidIDOR == 0 {
		t.Fatalf("summary=%#v cases=%v", report.Summary, cases)
	}
}

func TestRunExecutesNumericIDORCasesOnlyForSubstantiveDataBaseline(t *testing.T) {
	testCases := []struct {
		name      string
		baseline  string
		qualified bool
	}{
		{name: "substantive object", baseline: `{"id":10,"owner":"authorized-test-user"}`, qualified: true},
		{name: "trivial echoed identifier", baseline: `{"id":10}`, qualified: false},
		{name: "non JSON catch all", baseline: `<html>catch all</html>`, qualified: false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var idorCases atomic.Int32
			client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				if strings.HasPrefix(request.Header.Get("X-SJ-Test-Case"), "idor_") || strings.HasPrefix(request.Header.Get("X-SJ-Test-Case"), "idor_range:") {
					idorCases.Add(1)
					return fuzzResponse(request, http.StatusOK, `{"id":11,"owner":"other"}`)
				}
				return fuzzResponse(request, http.StatusOK, testCase.baseline)
			})}
			idRange := apitest.NumericRange{Start: 1, End: 3}
			report, err := run(t.Context(), client, []pentestreport.Operation{{
				Method: http.MethodGet, Status: http.StatusOK, URL: "https://api.example/users/10", Target: "/users/10",
			}}, Options{MaxRequests: 20, Delay: minimumRequestDelay, MaxCasesPerOperation: 8, IDORRange: &idRange}, noWait)
			if err != nil {
				t.Fatal(err)
			}
			if testCase.qualified && (idorCases.Load() == 0 || report.Summary.QualifiedIDORBaselines != 1) {
				t.Fatalf("valid baseline did not release IDOR cases: count=%d summary=%#v", idorCases.Load(), report.Summary)
			}
			if !testCase.qualified && (idorCases.Load() != 0 || report.Summary.RejectedIDORBaselines != 1) {
				t.Fatalf("invalid baseline released IDOR cases: count=%d summary=%#v", idorCases.Load(), report.Summary)
			}
		})
	}
}

func TestRunQualifiesIDORBaselinePerIdentity(t *testing.T) {
	seen := make(map[string][]string)
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		identity := request.Header.Get("X-Test-Identity")
		seen[identity] = append(seen[identity], request.Header.Get("X-SJ-Test-Case"))
		if identity == "valid" {
			return fuzzResponse(request, http.StatusOK, `{"id":10,"owner":"valid"}`)
		}
		return fuzzResponse(request, http.StatusOK, `{"ok":false,"info":"invalid identity context"}`)
	})}
	idRange := apitest.NumericRange{Start: 1, End: 2}
	report, err := run(t.Context(), client, []pentestreport.Operation{{
		Method: http.MethodGet, Status: http.StatusOK, URL: "https://api.example/users/10", Target: "/users/10",
	}}, Options{
		MaxRequests: 30, Delay: minimumRequestDelay, MaxCasesPerOperation: 8, IDORRange: &idRange,
		Identities: []Identity{
			{Name: "valid", Headers: map[string]string{"X-Test-Identity": "valid"}},
			{Name: "invalid", Headers: map[string]string{"X-Test-Identity": "invalid"}},
		},
	}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range seen["invalid"] {
		if strings.HasPrefix(testCase, "idor_") || strings.HasPrefix(testCase, "idor_range:") {
			t.Fatalf("invalid identity received IDOR case: %#v", seen)
		}
	}
	if report.Summary.QualifiedIDORBaselines != 1 || report.Summary.RejectedIDORBaselines != 1 {
		t.Fatalf("summary=%#v cases=%#v", report.Summary, seen)
	}
}

func noWait(_ context.Context, _ time.Duration) error { return nil }
