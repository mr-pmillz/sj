package report

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeCorrelatesAnonymousPersistentWriteReadback(t *testing.T) {
	operations := []Operation{
		{
			Origin: "automate", Source: "https://spades.example/openapi.json", Method: "POST", Status: 201,
			Target: "/entities", URL: "https://spades.example/entities",
			RequestBody:  `{"entity_id":"testvalue","value":"before"}`,
			ResponseBody: `{"entity_id":"testvalue","value":"before"}`,
		},
		{
			Origin: "automate", Source: "https://spades.example/openapi.json", Method: "GET", Status: 200,
			Target: "/entities/testvalue", URL: "https://spades.example/entities/testvalue",
			ResponseBody: `{"entity_id":"testvalue","value":"before"}`,
		},
		{
			Origin: "automate", Source: "https://spades.example/openapi.json", Method: "PUT", Status: 200,
			Target: "/entities/testvalue", URL: "https://spades.example/entities/testvalue",
			RequestBody:  `{"entity_id":"testvalue","value":"after"}`,
			ResponseBody: `{"entity_id":"testvalue","value":"after"}`,
		},
		{
			Origin: "fuzz", Source: "https://spades.example", Method: "GET", Status: 200,
			Target: "/entities/testvalue", URL: "https://spades.example/entities/testvalue",
			ResponseBody: `{"entity_id":"testvalue","value":"after"}`,
		},
	}

	report := Analyze(Dataset{Operations: operations}, AnalyzeOptions{
		GeneratedAt: time.Unix(0, 0).UTC(), MaxEvidence: 10,
	})
	finding := requireFinding(t, report, "PENTEST-PERSISTENT-UNAUTH-WRITE")
	if finding.Severity != SeverityHigh || finding.Count != 1 {
		t.Fatalf("persistent finding = %#v", finding)
	}
	if len(finding.Evidence) != 4 {
		t.Fatalf("persistent proof = %#v", finding.Evidence)
	}
	for index, method := range []string{"POST", "GET", "PUT", "GET"} {
		if finding.Evidence[index].Method != method || finding.Evidence[index].ResponseBody == "" {
			t.Fatalf("proof[%d] = %#v", index, finding.Evidence[index])
		}
	}
	for _, noisyID := range []string{
		"PENTEST-STATE-CHANGE-CANDIDATE", "PENTEST-IDOR-CANDIDATE", "PENTEST-READ-ACCESS",
	} {
		if hasFinding(report, noisyID) {
			t.Fatalf("proof-chain operation also emitted %s: %#v", noisyID, report.Findings)
		}
	}
}

func TestAnalyzeRequiresAnonymousSubstantiveReadbackForPersistentWrite(t *testing.T) {
	tests := map[string][]Operation{
		"no readback": {
			{Method: "POST", Status: 201, Target: "/entities", RequestBody: `{"entity_id":"x"}`, ResponseBody: `{"entity_id":"x"}`},
		},
		"failure envelope": {
			{Method: "POST", Status: 200, Target: "/entities", RequestBody: `{"entity_id":"x"}`, ResponseBody: `{"ok":false,"error":"denied"}`},
			{Method: "GET", Status: 200, Target: "/entities/x", ResponseBody: `{"ok":false,"error":"missing"}`},
		},
		"authenticated identity": {
			{Identity: "alice", AuthContext: "authenticated", Method: "POST", Status: 201, Target: "/entities", RequestBody: `{"entity_id":"x"}`, ResponseBody: `{"entity_id":"x"}`},
			{Identity: "alice", AuthContext: "authenticated", Method: "GET", Status: 200, Target: "/entities/x", ResponseBody: `{"entity_id":"x"}`},
		},
		"unrelated read": {
			{Method: "POST", Status: 201, Target: "/entities", RequestBody: `{"entity_id":"x"}`, ResponseBody: `{"entity_id":"x"}`},
			{Method: "GET", Status: 200, Target: "/entities/y", ResponseBody: `{"entity_id":"y"}`},
		},
		"single generic scanner value": {
			{Method: "POST", Status: 201, Target: "/entities", RequestBody: `{"name":"testvalue"}`, ResponseBody: `{"name":"testvalue"}`},
			{Method: "GET", Status: 200, Target: "/entities/testvalue", ResponseBody: `{"name":"testvalue"}`},
		},
		"truncated readback": {
			{Method: "POST", Status: 201, Target: "/entities", RequestBody: `{"entity_id":"x"}`, ResponseBody: `{"entity_id":"x"}`},
			{Method: "GET", Status: 200, Target: "/entities/x", ResponseBody: `{"entity_id":"x"}`, ResponseTruncated: true},
		},
	}
	for name, operations := range tests {
		t.Run(name, func(t *testing.T) {
			report := Analyze(Dataset{Operations: operations}, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
			if hasFinding(report, "PENTEST-PERSISTENT-UNAUTH-WRITE") {
				t.Fatalf("false persistent finding: %#v", report.Findings)
			}
		})
	}
}

func TestPersistentReadbackIndexHandlesRelativeURLsAndUnrelatedLargeCorpus(t *testing.T) {
	operations := make([]Operation, 0, 4002)
	for index := 0; index < 2000; index++ {
		operations = append(operations, Operation{
			Method: "POST", Status: 201, Target: fmt.Sprintf("/unrelated/%d", index),
			RequestBody: `{"marker":"write-only"}`, ResponseBody: `{"marker":"write-only"}`,
		})
	}
	operations = append(operations,
		Operation{Method: "POST", Status: 201, Target: "/entities?source=test", RequestBody: `{"entity_id":"testvalue"}`, ResponseBody: `{"entity_id":"testvalue"}`},
		Operation{Method: "GET", Status: 200, Target: "/entities/testvalue?view=full", ResponseBody: `{"entity_id":"testvalue"}`},
	)
	for index := 0; index < 2000; index++ {
		operations = append(operations, Operation{
			Method: "GET", Status: 200, Target: fmt.Sprintf("/other/%d", index), ResponseBody: `{"marker":"write-only"}`,
		})
	}

	report := Analyze(Dataset{Operations: operations}, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	finding := requireFinding(t, report, "PENTEST-PERSISTENT-UNAUTH-WRITE")
	if finding.Count != 1 || len(finding.Evidence) != 2 {
		t.Fatalf("indexed persistence proof = %#v", finding)
	}
}

func TestAnalyzeGroupsVerboseDatabaseDisclosureByEndpointFamily(t *testing.T) {
	operations := make([]Operation, 0, 194)
	for companyID := 1; companyID <= 97; companyID++ {
		for _, endpoint := range []string{"/didi/1/detail", "/invoice_log/1"} {
			operations = append(operations, Operation{
				Origin: "fuzz", Method: "GET", Status: 500, Target: endpoint,
				URL:          fmt.Sprintf("https://api.example.test%s?IdCompany=%d&lng=es", endpoint, companyID),
				ResponseBody: `{"error":"(pyodbc.ProgrammingError) Microsoft ODBC Driver 17 for SQL Server: Invalid object name 'integracion.InvoiceLog'; SQLAlchemy query failed; procedure spApiExternalAdd; parameters: IdCompany"}`,
			})
		}
	}

	report := Analyze(Dataset{Operations: operations}, AnalyzeOptions{
		GeneratedAt: time.Unix(0, 0).UTC(), MaxEvidence: 5,
	})
	finding := requireFinding(t, report, "PENTEST-VERBOSE-BACKEND-DISCLOSURE")
	if finding.Severity != SeverityMedium || finding.Count != 2 {
		t.Fatalf("verbose disclosure finding = %#v", finding)
	}
	if len(finding.Evidence) != 2 {
		t.Fatalf("expected one proof per endpoint family, got %#v", finding.Evidence)
	}
	if finding.Evidence[0].ResponseBody == "" || finding.Evidence[1].ResponseBody == "" {
		t.Fatalf("response proof was omitted: %#v", finding.Evidence)
	}
	if hasFinding(report, "PENTEST-SERVER-ERROR") {
		t.Fatalf("bare 5xx finding survived: %#v", report.Findings)
	}
}

func TestAnalyzeDetectsStructuredExceptionBacktrace(t *testing.T) {
	report := Analyze(Dataset{Operations: []Operation{{
		Method: "POST", Status: 500, URL: "https://api.example/auth",
		ResponseBody: `{"type":"JOSE_Exception_EncryptionFailed","filename":"C:\\inetpub\\wwwroot\\api\\JWE.php","line_number":166,"backtrace":[{"file":"C:\\inetpub\\wwwroot\\api\\JWE.php","line":39,"function":"encrypt"}]}`,
	}}}, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	finding := requireFinding(t, report, "PENTEST-VERBOSE-BACKEND-DISCLOSURE")
	if finding.Severity != SeverityMedium || finding.Count != 1 {
		t.Fatalf("structured backtrace finding = %#v", finding)
	}
}

func TestAnalyzeLabelsSourceSuppliedRedactionWithoutRemovingEvidence(t *testing.T) {
	const body = `{"error":"stack trace","bearerToken":"REDACTED"}`
	report := Analyze(Dataset{Operations: []Operation{{
		Method: "GET", Status: 500, URL: "https://api.example/error", ResponseBody: body,
	}}}, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	finding := requireFinding(t, report, "PENTEST-VERBOSE-BACKEND-DISCLOSURE")
	if finding.Evidence[0].ResponseBody != body || !strings.Contains(finding.Evidence[0].Note, "captured source payload") {
		t.Fatalf("source-supplied redaction provenance = %#v", finding.Evidence[0])
	}
}

func TestAnalyzeDetectsActualPIIAndIgnoresSyntheticOrInvalidCandidates(t *testing.T) {
	operations := []Operation{
		{Method: "GET", Status: 200, Target: "/customer/1", ResponseBody: `{"email":"person@customer.co","card":"4111111111111111"}`},
		{Method: "GET", Status: 200, Target: "/customer/2", ResponseBody: `{"id":"1492030000000000","email":"probe@sj.invalid"}`},
	}
	report := Analyze(Dataset{Operations: operations}, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	finding := requireFinding(t, report, "PENTEST-SENSITIVE-DATA-EXPOSURE")
	if finding.Severity != SeverityHigh || finding.Count != 1 || len(finding.Evidence) != 1 {
		t.Fatalf("PII finding = %#v", finding)
	}
	if note := finding.Evidence[0].Note; !strings.Contains(note, "email") || !strings.Contains(note, "payment card candidate") {
		t.Fatalf("PII type-only note = %q", note)
	}
}

func TestAnalyzeDoesNotTreatIntendedTokenIssuanceAsCredentialLeak(t *testing.T) {
	report := Analyze(Dataset{Operations: []Operation{{
		Method: "POST", Status: 200, URL: "https://api.example/oauth/token", Target: "/oauth/token",
		ResponseBody: `{"access_token":"abcdefghijklmnop","token_type":"Bearer"}`,
	}}}, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	if hasFinding(report, "PENTEST-SENSITIVE-DATA-EXPOSURE") {
		t.Fatalf("intended token issuance was promoted: %#v", report.Findings)
	}
}

func TestAnalyzeDoesNotSuppressCredentialLeaksOnNonIssuanceAuthRoutes(t *testing.T) {
	report := Analyze(Dataset{Operations: []Operation{{
		Method: "GET", Status: 200, URL: "https://api.example/session/debug", Target: "/session/debug",
		ResponseBody: `{"access_token":"abcdefghijklmnop"}`,
	}}}, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	if !hasFinding(report, "PENTEST-SENSITIVE-DATA-EXPOSURE") {
		t.Fatalf("credential leak on non-issuance route was suppressed: %#v", report.Findings)
	}
}

func TestAnalyzeOmitsUnprovenHeuristicNoise(t *testing.T) {
	dataset := Dataset{Operations: []Operation{
		{Method: "GET", Status: 200, Target: "/users/123", ResponseBody: `{"id":123}`},
		{Method: "POST", Status: 201, Target: "/checkout", RequestBody: `{"item":"x"}`, ResponseBody: `{"accepted":true}`},
		{Method: "GET", Status: 500, Target: "/search", ResponseBody: `{"error":"request failed"}`},
		{Method: "GET", Status: 200, Target: "/webhook", ResponseBody: `{"enabled":true}`},
		{Method: "GET", Status: 200, Target: "/download", ResponseBody: `{"public":true}`},
		{Method: "POST", Status: 200, Target: "/auth", ResponseBody: `{"ok":false,"error":"denied"}`},
	}}
	report := Analyze(dataset, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	if len(report.Findings) != 0 {
		t.Fatalf("unproven heuristics were rendered as findings: %#v", report.Findings)
	}
}

func TestAnalyzeOmitsDatabaseProductNamesWithoutErrorDisclosure(t *testing.T) {
	report := Analyze(Dataset{Operations: []Operation{{
		Method: "GET", Status: 200, Target: "/docs/databases",
		ResponseBody: `{"supported":["MySQL","PostgreSQL","SQLite","SQL Server"]}`,
	}}}, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	if hasFinding(report, "PENTEST-VERBOSE-BACKEND-DISCLOSURE") {
		t.Fatalf("product documentation was classified as an error disclosure: %#v", report.Findings)
	}
}

func TestAnalyzeDetectsPydanticAndUpstreamClientDisclosures(t *testing.T) {
	report := Analyze(Dataset{Operations: []Operation{
		{Method: "GET", Status: 500, URL: "https://api.example/v1/restaurant/closest.json", ResponseBody: `14 validation errors for RestaurantClosestSchema: field required [type=missing, input_type=dict] https://errors.pydantic.dev/2.10/v/missing`},
		{Method: "GET", Status: 500, URL: "https://api.example/v1/customer-device/appMain.js", ResponseBody: `HTTPSConnectionPool(host='internal-upstream', port=443): Max retries exceeded with url: /config (Caused by NameResolutionError("urllib3.connection.HTTPSConnection object: [Errno -2] Name or service not known"))`},
	}}, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC(), MaxEvidence: 5})
	finding := requireFinding(t, report, "PENTEST-IMPLEMENTATION-DIAGNOSTIC-DISCLOSURE")
	if finding.Severity != SeverityLow || finding.Count != 2 || len(finding.Evidence) != 2 {
		t.Fatalf("disclosure grouping = %#v", finding)
	}
	if hasFinding(report, "PENTEST-VERBOSE-BACKEND-DISCLOSURE") {
		t.Fatalf("lower-specificity diagnostics were promoted to medium: %#v", report.Findings)
	}
}

func TestAnalyzeDoesNotTreatPublicAssetHomePathAsStackTrace(t *testing.T) {
	report := Analyze(Dataset{Operations: []Operation{{
		Method: "GET", Status: 200, URL: "https://api.example/config",
		ResponseBody: `{"icon":"https://cdn.example/mobile/home/callCenter.svg"}`,
	}}}, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	if len(report.Findings) != 0 {
		t.Fatalf("public asset URL was classified as a stack trace: %#v", report.Findings)
	}
}

func TestAnalyzeDoesNotTreatPublicClientDatabaseCodeAsBackendError(t *testing.T) {
	report := Analyze(Dataset{Operations: []Operation{{
		Method: "GET", Status: 200, URL: "https://api.example/app.js", ContentType: "application/javascript",
		ResponseBody: `window.sqlitePlugin.openDatabase({name:"client.db"}); function invalidForm(){ return false }; CREATE TABLE IF NOT EXISTS local_cache (id integer);`,
	}}}, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	if len(report.Findings) != 0 {
		t.Fatalf("public client-side database code was classified as a backend error: %#v", report.Findings)
	}
}

func TestAnalyzeKeepsCoverageFailuresOutOfSecurityFindings(t *testing.T) {
	report := Analyze(Dataset{Failures: []Failure{{Source: "https://api.example/openapi.json", Error: "fetch failed"}}}, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	if len(report.Findings) != 0 {
		t.Fatalf("coverage condition was rendered as a vulnerability: %#v", report.Findings)
	}
	if report.Metrics.Failures != 1 {
		t.Fatalf("coverage failure disappeared from metrics: %#v", report.Metrics)
	}
}

func TestAnalyzeSuppressesSameIdentityImportedIDORAndRegexOnlyPII(t *testing.T) {
	const targetURL = "https://api.example/users/testvalue"
	dataset := Dataset{
		Operations: []Operation{
			{Origin: "fuzz", Identity: "alice", Method: "GET", Status: 200, URL: "https://api.example/users/1", BaselineURL: targetURL, ResponseBody: `{"id":1}`},
			{Origin: "fuzz", Identity: "alice", Method: "GET", Status: 200, URL: "https://api.example/users/2", BaselineURL: targetURL, ResponseBody: `{"id":2}`},
		},
		ImportedFindings: []ImportedFinding{
			{Severity: "high", Category: "idor_enumeration", Method: "GET", URL: targetURL, Evidence: "successful_ids=2"},
			{Severity: "high", Category: "pii_exposure", Method: "GET", URL: "https://api.example/missing", Evidence: "matched_types=payment card candidate"},
		},
	}
	report := Analyze(dataset, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	if len(report.Findings) != 0 {
		t.Fatalf("unverified imported candidates survived: %#v", report.Findings)
	}
}

func requireFinding(t *testing.T, report Report, id string) Finding {
	t.Helper()
	for _, finding := range report.Findings {
		if finding.ID == id {
			return finding
		}
	}
	t.Fatalf("missing %s in %#v", id, report.Findings)
	return Finding{}
}
