package fuzz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

func TestRunIsolatesRateLimitedOriginAndContinuesOtherTargets(t *testing.T) {
	var calls []string
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls = append(calls, request.URL.Host+request.URL.Path)
		if request.URL.Host == "limited.example" {
			return fuzzResponse(request, http.StatusTooManyRequests, `{"error":"slow down"}`)
		}
		return fuzzResponse(request, http.StatusOK, `{"status":"ok"}`)
	})}
	operations := []pentestreport.Operation{
		{Method: "GET", URL: "https://limited.example/a", Target: "/a"},
		{Method: "GET", URL: "https://limited.example/b", Target: "/b"},
		{Method: "GET", URL: "https://healthy.example/c", Target: "/c"},
	}
	report, err := run(t.Context(), client, operations, Options{
		MaxRequests: 20, Delay: minimumRequestDelay, ContinueOnTargetError: true,
	}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Summary.RateLimited || report.Summary.RateLimitedOrigins != 1 || report.Summary.SkippedIsolated == 0 {
		t.Fatalf("summary = %#v", report.Summary)
	}
	joinedCalls := strings.Join(calls, ",")
	if strings.Contains(joinedCalls, "limited.example/b") || !strings.Contains(joinedCalls, "healthy.example/c") {
		t.Fatalf("calls = %v", calls)
	}
}

func TestRunIsolatesRepeatedTransportFailureAndContinuesOtherTargets(t *testing.T) {
	var calls []string
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls = append(calls, request.URL.Host+request.URL.Path)
		if request.URL.Host == "offline.example" {
			return nil, fmt.Errorf("target unavailable")
		}
		return fuzzResponse(request, http.StatusOK, `{"status":"ok"}`)
	})}
	operations := []pentestreport.Operation{
		{Method: "GET", URL: "https://offline.example/a", Target: "/a"},
		{Method: "GET", URL: "https://offline.example/b", Target: "/b"},
		{Method: "GET", URL: "https://offline.example/c", Target: "/c"},
		{Method: "GET", URL: "https://offline.example/d", Target: "/d"},
		{Method: "GET", URL: "https://healthy.example/e", Target: "/e"},
	}
	report, err := run(t.Context(), client, operations, Options{
		MaxRequests: 20, Delay: minimumRequestDelay, ContinueOnTargetError: true,
	}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.TransportLimitedOrigins != 1 || report.Summary.SkippedIsolated == 0 {
		t.Fatalf("summary = %#v", report.Summary)
	}
	joinedCalls := strings.Join(calls, ",")
	if strings.Contains(joinedCalls, "offline.example/d") || !strings.Contains(joinedCalls, "healthy.example/e") {
		t.Fatalf("calls = %v", calls)
	}
}

func TestRunDoesNotIsolateAmbiguousSharedProxyFailure(t *testing.T) {
	var calls []string
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls = append(calls, request.URL.String())
		return nil, errors.New("shared proxy unavailable")
	})}
	operations := []pentestreport.Operation{
		{Method: "GET", URL: "https://first.example/a", Target: "/a"},
		{Method: "GET", URL: "https://first.example/b", Target: "/b"},
		{Method: "GET", URL: "https://first.example/c", Target: "/c"},
		{Method: "GET", URL: "https://first.example/d", Target: "/d"},
	}
	report, err := run(t.Context(), client, operations, Options{
		MaxRequests: 20, Delay: minimumRequestDelay, ContinueOnTargetError: true,
		TargetOriginTransportError: func(error) bool { return false },
	}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != len(report.Probes) || report.Summary.TransportLimitedOrigins != 0 ||
		report.Summary.SkippedIsolated != 0 {
		t.Fatalf("calls=%d probes=%d summary=%#v", len(calls), len(report.Probes), report.Summary)
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
		return fuzzResponse(request, http.StatusInternalServerError, `{"email":"private-person@customer.co","error":"stack trace /home/service/main.go:10"}`)
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

func TestRunClassifiesSQLAlchemyDatabaseDisclosure(t *testing.T) {
	const responseBody = `{"detail":"Database failure: (pyodbc.IntegrityError) ('23000', \"[Microsoft][ODBC Driver 17 for SQL Server][SQL Server] Cannot insert NULL into column 'CallbackUrl', table 'tenantdb.dbo.ApiAudit'; constraint 'FK_ApiAudit_Tenant'.\")\n[SQL: EXEC spAuditAdd @payload = ?]\n[parameters: ('omitted',)]\n(Background on this error at: https://sqlalche.me/e/20/gkpj)"}`
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return fuzzResponse(request, http.StatusInternalServerError, responseBody)
	})}
	report, err := run(t.Context(), client, []pentestreport.Operation{{
		Method: http.MethodGet, URL: "https://api.example/audit/1/detail?tenantId=1&locale=en", Target: "/audit/1/detail",
	}}, Options{MaxRequests: 10, Delay: minimumRequestDelay}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Probes) == 0 || !report.Probes[0].VerboseError {
		t.Fatalf("probe did not classify database disclosure: %#v", report.Probes)
	}
	for _, finding := range report.Findings {
		if finding.Category == "verbose_error" && strings.Contains(finding.Evidence, "database_driver") && strings.Contains(finding.Evidence, "sql_statement") {
			return
		}
	}
	t.Fatalf("database disclosure finding missing: %#v", report.Findings)
}

func TestAnalyzeProbesDetectsStructuredExceptionBacktrace(t *testing.T) {
	findings := AnalyzeProbes([]ProbeResult{{
		Method: "POST", URL: "https://api.example/auth", Status: 500,
		analysisBody: []byte(`{"type":"JOSE_Exception_EncryptionFailed","filename":"C:\\inetpub\\wwwroot\\api\\JWE.php","line_number":166,"backtrace":[{"file":"C:\\inetpub\\wwwroot\\api\\JWE.php","line":39}]}`),
	}})
	if len(findings) != 1 || findings[0].Category != "verbose_error" || findings[0].Severity != "medium" || !strings.Contains(findings[0].Evidence, "stack_trace") {
		t.Fatalf("structured backtrace finding = %#v", findings)
	}
}

func TestAnalyzeProbesClassifiesPydanticAndUpstreamDisclosuresAsLowButNotNoneTypeAlone(t *testing.T) {
	probes := []ProbeResult{
		{Method: "GET", URL: "https://api.example/schema", Status: 500, analysisBody: []byte(`3 validation errors for RestaurantClosestSchema [type=missing, input_type=dict] https://errors.pydantic.dev/2.10/v/missing`)},
		{Method: "GET", URL: "https://api.example/upstream", Status: 500, analysisBody: []byte(`HTTPSConnectionPool host=internal: NameResolutionError from urllib3.connection: Name or service not known`)},
		{Method: "GET", URL: "https://api.example/ambiguous", Status: 500, analysisBody: []byte(`the JSON object must be str, bytes or bytearray, not NoneType`)},
	}
	findings := AnalyzeProbes(probes)
	implementation := make([]Finding, 0)
	for _, finding := range findings {
		if finding.Category == "implementation_disclosure" {
			implementation = append(implementation, finding)
		}
	}
	if len(implementation) != 2 {
		t.Fatalf("implementation findings = %#v", implementation)
	}
	for _, finding := range implementation {
		if finding.Severity != "low" {
			t.Fatalf("implementation diagnostic severity = %#v", finding)
		}
		if strings.Contains(finding.URL, "/ambiguous") {
			t.Fatalf("NoneType-only response was promoted: %#v", finding)
		}
	}
}

func TestAnalyzeProbesSuppressesBareGenericServerErrors(t *testing.T) {
	probes := []ProbeResult{{
		Method: http.MethodGet, URL: "https://api.example/items/1", Case: "bad_character", Category: "bad_character",
		Status: http.StatusInternalServerError, ResponseBytes: len(`{"error":"internal server error"}`),
		analysisBody: []byte(`{"error":"internal server error"}`),
	}}
	for _, finding := range AnalyzeProbes(probes) {
		if finding.Category == "server_error" || finding.Category == "verbose_error" {
			t.Fatalf("generic 500 became an actionable finding: %#v", finding)
		}
	}
}

func TestAnalyzeProbesSuppressesUncorroboratedDatabaseProductAndSchemaText(t *testing.T) {
	probes := []ProbeResult{{
		Method: "GET", URL: "https://api.example/docs", Status: 200,
		analysisBody: []byte(`Microsoft SQL Server supports table [dbo.docs] and column [title]`),
	}}
	if findings := AnalyzeProbes(probes); len(findings) != 0 {
		t.Fatalf("uncorroborated database documentation was promoted: %#v", findings)
	}
}

func TestAnalyzeProbesSuppressesIntendedTokenIssuance(t *testing.T) {
	probes := []ProbeResult{{
		Method: "POST", URL: "https://api.example/oauth/token", Status: 200,
		analysisBody: []byte(`{"access_token":"abcdefghijklmnop","token_type":"Bearer"}`),
	}}
	if findings := AnalyzeProbes(probes); len(findings) != 0 {
		t.Fatalf("intended token issuance was promoted: %#v", findings)
	}
}

func TestAnalyzeProbesDoesNotSuppressCredentialLeaksOnNonIssuanceAuthRoutes(t *testing.T) {
	probes := []ProbeResult{{
		Method: "GET", URL: "https://api.example/auth/profile", Status: 200,
		analysisBody: []byte(`{"access_token":"abcdefghijklmnop"}`),
	}}
	findings := AnalyzeProbes(probes)
	if len(findings) != 1 || findings[0].Category != "pii_exposure" {
		t.Fatalf("credential leak on non-issuance route was suppressed: %#v", findings)
	}
}

func TestAnalyzeProbesDeduplicatesDisclosuresByEndpointAndSignature(t *testing.T) {
	const disclosure = `{"detail":"(pyodbc.IntegrityError) [Microsoft][ODBC Driver 17 for SQL Server][SQL Server] table 'tenantdb.dbo.ApiAudit' column 'CallbackUrl' [SQL: EXEC spAuditAdd @payload = ?] [parameters: ('omitted',)] https://sqlalche.me/e/20/gkpj"}`
	probes := make([]ProbeResult, 0, 97)
	for companyID := 1; companyID <= 97; companyID++ {
		body := []byte(disclosure)
		probes = append(probes, ProbeResult{
			Method: http.MethodGet, URL: fmt.Sprintf("https://api.example/audit/1/detail?tenantId=%d&locale=en", companyID),
			Case: fmt.Sprintf("idor_range:query.tenantId:%d", companyID), Category: "idor_range", Identity: "anonymous",
			Status: http.StatusInternalServerError, ResponseBytes: len(body), analysisBody: body,
		})
	}
	findings := AnalyzeProbes(probes)
	var verbose []Finding
	for _, finding := range findings {
		if finding.Category == "verbose_error" {
			verbose = append(verbose, finding)
		}
		if finding.Category == "server_error" {
			t.Fatalf("database disclosure should not also emit generic server_error: %#v", finding)
		}
	}
	if len(verbose) != 1 {
		t.Fatalf("verbose findings = %#v", verbose)
	}
	if !strings.Contains(verbose[0].URL, "/audit/{id}/detail") || !strings.Contains(verbose[0].URL, "tenantId={value}") {
		t.Fatalf("finding URL was not normalized: %#v", verbose[0])
	}
	if !strings.Contains(verbose[0].Evidence, "matching_probes=97") || strings.Count(verbose[0].Evidence, "https://") > 3 {
		t.Fatalf("finding evidence was not grouped and bounded: %#v", verbose[0])
	}
}

func TestAnalyzeProbesDeduplicatesPIIWithoutCopyingMatchedValues(t *testing.T) {
	const privateEmail = "person@customer.co"
	const privateToken = "secret-token-value"
	probes := make([]ProbeResult, 0, 5)
	for identifier := 1; identifier <= 5; identifier++ {
		probes = append(probes, ProbeResult{
			Method: http.MethodGet, URL: fmt.Sprintf("https://api.example/users/%s/%d?q=%s&expand=profile&token=%s", privateEmail, identifier, privateEmail, privateToken),
			Status: http.StatusOK, Identity: "anonymous", PIITypes: []string{"email"},
			analysisBody: []byte(`{"email":"` + privateEmail + `"}`),
		})
	}
	findings := AnalyzeProbes(probes)
	var pii []Finding
	for _, finding := range findings {
		if finding.Category == "pii_exposure" {
			pii = append(pii, finding)
		}
	}
	if len(pii) != 1 {
		t.Fatalf("PII findings = %#v", pii)
	}
	joined := pii[0].URL + " " + pii[0].Evidence
	if strings.Contains(joined, privateEmail) || strings.Contains(joined, url.QueryEscape(privateEmail)) || strings.Contains(joined, privateToken) || !strings.Contains(pii[0].Evidence, "matching_probes=5") || strings.Count(joined, "https://") > 4 {
		t.Fatalf("PII evidence leaked or was not bounded: %s", joined)
	}
}

func TestExposureAnalysisHelpersHandleStoredAndInvalidInputs(t *testing.T) {
	if body := probeResponseBody(ProbeResult{ResponseBody: `{"detail":"stored"}`}); string(body) != `{"detail":"stored"}` {
		t.Fatalf("stored response body = %q", body)
	}
	if body := probeResponseBody(ProbeResult{}); body != nil {
		t.Fatalf("empty response body = %q", body)
	}
	if types := detectVerboseDisclosureTypes(nil); types != nil {
		t.Fatalf("empty disclosure types = %v", types)
	}
	if endpoint := normalizedEndpointTemplate("https://api.example/%zz"); endpoint != "<invalid-url>" {
		t.Fatalf("invalid endpoint template = %q", endpoint)
	}
	if representative := safeRepresentativeURL("https://api.example/%zz"); representative != "" {
		t.Fatalf("invalid representative URL = %q", representative)
	}
	longURL := "https://api.example/items?q=" + strings.Repeat("a", maximumRepresentativeLength)
	if representative := safeRepresentativeURL(longURL); len(representative) != maximumRepresentativeLength+3 || !strings.HasSuffix(representative, "...") {
		t.Fatalf("long representative URL was not bounded: length=%d", len(representative))
	}
	if values := sortedUniqueStrings([]string{" email ", "", "email", "phone"}); strings.Join(values, ",") != "email,phone" {
		t.Fatalf("sorted unique values = %v", values)
	}
}

func TestRunRecordsCredentialPresenceWithoutPersistingCredentialValues(t *testing.T) {
	const credential = "Bearer private-test-credential"
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return fuzzResponse(request, http.StatusOK, `{"status":"ok"}`)
	})}
	report, err := run(t.Context(), client, []pentestreport.Operation{{
		Method: http.MethodGet, URL: "https://api.example/health", Target: "/health",
	}}, Options{
		MaxRequests: 10, Delay: minimumRequestDelay,
		Identities: []Identity{
			{Name: "anonymous", Headers: map[string]string{"X-Trace-ID": "trace-only"}},
			{Name: "api-user", Headers: map[string]string{"Authorization": credential}},
		},
	}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	contexts := make(map[string]string)
	for _, probe := range report.Probes {
		contexts[probe.Identity] = probe.AuthContext
	}
	if contexts["anonymous"] != "anonymous" || contexts["api-user"] != "authenticated" {
		t.Fatalf("auth contexts = %#v", contexts)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), credential) {
		t.Fatalf("credential value leaked into report: %s", encoded)
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
