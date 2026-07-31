package report

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/config"
)

func TestLoadDeduplicatesEquivalentResultFormats(t *testing.T) {
	directory := t.TempDir()
	writeReportFixture(t, directory, "brute.json", `[{"target":"https://api.example","specs_found":[{"url":"https://api.example/openapi.json","content_type":"application/json","openapi_version":"3.1.0"}],"summary":{"urls_tested":10,"specs_found_count":1,"responses_2xx":1,"responses_4xx":9,"errors":0}}]`)
	writeReportFixture(t, directory, "brute.jsonl", `{"target":"https://api.example","url":"https://api.example/openapi.json","content_type":"application/json","openapi_version":"3.1.0"}`+"\n")
	writeReportFixture(t, directory, "automate.json", `{"results":[{"source":"https://api.example/openapi.json","method":"GET","status":200,"target":"/users/1"},{"source":"https://api.example/openapi.json","method":"DELETE","status":204,"target":"/users/1"}],"source_failures":[{"source":"https://broken.example/openapi.json","error":"invalid specification"}],"coverage_gaps":[{"origin":"https://limited.example","reason":"rate-limited","skipped":3}]}`)
	writeReportFixture(t, directory, "automate.jsonl", `{"source":"https://api.example/openapi.json","method":"GET","status":200,"target":"/users/1"}`+"\n"+`{"source":"https://api.example/openapi.json","method":"DELETE","status":204,"target":"/users/1"}`+"\n")
	writeReportFixture(t, directory, "automate.csv", "source,method,status,target\nhttps://api.example/openapi.json,GET,200,/users/1\nhttps://api.example/openapi.json,DELETE,204,/users/1\n")
	writeReportFixture(t, directory, "brute.csv", "target,url,content_type,openapi_version,title,description\nhttps://api.example,https://api.example/openapi.json,application/json,3.1.0,Example,\n")
	writeReportFixture(t, directory, "brute.txt", "# Target: https://api.example\nhttps://api.example/openapi.json\n")
	writeReportFixture(t, directory, "failures.json", `[{"source":"https://api.example/bad.json","error":"invalid path"}]`)
	writeReportFixture(t, directory, "progress.log", "duplicate progress output\n")

	dataset, err := Load([]string{directory}, DefaultLoadOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(dataset.Operations) != 2 || len(dataset.Discoveries) != 1 || len(dataset.Targets) != 1 || len(dataset.Failures) != 3 {
		t.Fatalf("dataset = %#v", dataset)
	}
	if !dataset.Failures[0].Coverage && !dataset.Failures[1].Coverage {
		t.Fatalf("automate circuit coverage gap was not retained: %#v", dataset.Failures)
	}
	if dataset.RawRecords <= len(dataset.Operations)+len(dataset.Discoveries)+len(dataset.Failures) {
		t.Fatalf("raw records = %d, expected duplicate formats to be counted", dataset.RawRecords)
	}
	if dataset.DuplicateRecords == 0 || dataset.BruteURLsTested != 10 {
		t.Fatalf("dedup metrics = duplicates:%d tested:%d", dataset.DuplicateRecords, dataset.BruteURLsTested)
	}
	if len(dataset.IgnoredFiles) != 1 || !strings.HasSuffix(dataset.IgnoredFiles[0], "progress.log") {
		t.Fatalf("ignored files = %#v", dataset.IgnoredFiles)
	}
}

func TestLoadAndRenderPreservesWAFChallengeCoverage(t *testing.T) {
	directory := t.TempDir()
	path := writeReportFixture(t, directory, "brute.json", `{"target":"https://api.example","specs_found":[],"summary":{"urls_tested":3,"responses_4xx":3,"waf_challenge_detected":true,"waf_challenge_responses":3,"waf_challenge_limit_reached":true,"references_rejected":2,"references_skipped":4,"rate_limit_reached":true,"unavailable_limit_reached":true}}`)
	dataset, err := Load([]string{path}, DefaultLoadOptions())
	if err != nil {
		t.Fatal(err)
	}
	report := Analyze(dataset, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	var rendered bytes.Buffer
	if err := Write(report, "markdown", &rendered, config.ColorNever); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"WAF-challenged targets: **1**", "WAF challenge responses: **3**",
		"WAF-challenge-limited targets: **1**",
		"References rejected by policy: **2**", "References skipped by limits: **4**",
		"Rate-limited targets: **1**", "Unavailable-response-limited targets: **1**",
	} {
		if !strings.Contains(rendered.String(), expected) {
			t.Fatalf("markdown report omitted %q: %s", expected, rendered.String())
		}
	}
}

func TestLoadRejectsOversizedInputBeforeParsing(t *testing.T) {
	directory := t.TempDir()
	path := writeReportFixture(t, directory, "results.json", strings.Repeat("x", 33))
	options := DefaultLoadOptions()
	options.MaxFileBytes = 32
	if _, err := Load([]string{path}, options); err == nil || !strings.Contains(err.Error(), "32-byte") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadAcceptsExactFileAndRecordLimitsAndRejectsTheNextRecord(t *testing.T) {
	directory := t.TempDir()
	content := `{"results":[{"source":"one","method":"GET","status":200,"target":"/one"},{"source":"two","method":"GET","status":200,"target":"/two"}]}`
	path := writeReportFixture(t, directory, "results.json", content)
	options := DefaultLoadOptions()
	options.MaxFileBytes = int64(len(content))
	options.MaxRecords = 2
	dataset, err := Load([]string{path}, options)
	if err != nil {
		t.Fatalf("exact limits were rejected: %v", err)
	}
	if len(dataset.Operations) != 2 {
		t.Fatalf("operations = %#v", dataset.Operations)
	}
	options.MaxRecords = 1
	if _, err := Load([]string{path}, options); err == nil || !strings.Contains(err.Error(), "1-record") {
		t.Fatalf("record overflow error = %v", err)
	}
}

func TestLoadPreservesOperationOrderAndDistinctAuthenticationContexts(t *testing.T) {
	directory := t.TempDir()
	path := writeReportFixture(t, directory, "ordered-results.json", `{"results":[
		{"source":"https://api.example/openapi.json","method":"POST","status":201,"target":"/entities","url":"https://api.example/entities","auth_context":"anonymous","request_body":"{\"entity_id\":\"testvalue\"}","response_body":"{\"entity_id\":\"testvalue\",\"created\":true}"},
		{"source":"https://api.example/openapi.json","method":"GET","status":200,"target":"/entities/testvalue","url":"https://api.example/entities/testvalue","auth_context":"anonymous","response_body":"{\"entity_id\":\"testvalue\",\"created\":true}"},
		{"source":"https://api.example/openapi.json","method":"GET","status":200,"target":"/entities/testvalue","url":"https://api.example/entities/testvalue","auth_context":"authenticated","response_body":"{\"entity_id\":\"testvalue\",\"created\":true}"}
	]}`)

	dataset, err := Load([]string{path}, DefaultLoadOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(dataset.Operations) != 3 {
		t.Fatalf("operation occurrences were collapsed: %#v", dataset.Operations)
	}
	if dataset.Operations[0].Method != http.MethodPost || dataset.Operations[1].Method != http.MethodGet {
		t.Fatalf("file chronology was not preserved: %#v", dataset.Operations)
	}
	if dataset.Operations[1].AuthContext != "anonymous" || dataset.Operations[2].AuthContext != "authenticated" {
		t.Fatalf("authentication contexts were not preserved: %#v", dataset.Operations)
	}
	report := Analyze(dataset, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	if !hasFinding(report, "PENTEST-PERSISTENT-UNAUTH-WRITE") {
		t.Fatalf("ordered write/readback proof was not detected: %#v", report.Findings)
	}
}

func TestLoadRetainsIdenticalPreAndPostWriteReadOccurrences(t *testing.T) {
	directory := t.TempDir()
	path := writeReportFixture(t, directory, "repeated-read-results.json", `{"results":[
		{"source":"https://api.example/openapi.json","method":"GET","status":200,"target":"/entities/testvalue","url":"https://api.example/entities/testvalue","auth_context":"anonymous","response_body":"{\"entity_id\":\"testvalue\",\"label\":\"marker\"}"},
		{"source":"https://api.example/openapi.json","method":"POST","status":201,"target":"/entities","url":"https://api.example/entities","auth_context":"anonymous","request_body":"{\"entity_id\":\"testvalue\",\"label\":\"marker\"}","response_body":"{\"entity_id\":\"testvalue\",\"label\":\"marker\"}"},
		{"source":"https://api.example/openapi.json","method":"GET","status":200,"target":"/entities/testvalue","url":"https://api.example/entities/testvalue","auth_context":"anonymous","response_body":"{\"entity_id\":\"testvalue\",\"label\":\"marker\"}"}
	]}`)
	dataset, err := Load([]string{path}, DefaultLoadOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(dataset.Operations) != 3 || dataset.Operations[2].Method != http.MethodGet {
		t.Fatalf("identical read occurrences were collapsed or reordered: %#v", dataset.Operations)
	}
	report := Analyze(dataset, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	if !hasFinding(report, "PENTEST-PERSISTENT-UNAUTH-WRITE") {
		t.Fatalf("post-write repeated readback was unavailable to sequence analysis: %#v", report.Findings)
	}
}

func TestAnalyzeKeepsHeuristicsInMetricsAndOWASPCoverage(t *testing.T) {
	dataset := Dataset{
		Targets:     []string{"https://api.example"},
		Discoveries: []Discovery{{Target: "https://api.example", URL: "https://api.example/openapi.json", Version: "3.1.0"}},
		Operations: []Operation{
			{Source: "https://api.example/openapi.json", Method: "DELETE", Status: 204, Target: "/users/1"},
			{Source: "https://api.example/openapi.json", Method: "GET", Status: 200, Target: "/users/1"},
			{Source: "https://api.example/openapi.json", Method: "POST", Status: 201, Target: "/checkout"},
			{Source: "https://api.example/openapi.json", Method: "GET", Status: 500, Target: "/search"},
			{Source: "https://api.example/openapi.json", Method: "GET", Status: 302, Target: "/docs"},
			{Source: "https://api.example/openapi.json", Method: "GET", Status: 401, Target: "/admin"},
		},
		Failures: []Failure{{Source: "https://api.example/bad.json", Error: "invalid path"}},
	}
	report := Analyze(dataset, AnalyzeOptions{Title: "Authorized QA", GeneratedAt: time.Unix(0, 0).UTC(), MaxEvidence: 5})

	if len(report.Findings) != 0 || report.Severity.WeightedPoints != 0 {
		t.Fatalf("heuristic-only inputs were promoted to findings: %#v", report.Findings)
	}
	if report.Metrics.Failures != 1 {
		t.Fatalf("coverage failure was not retained as a metric: %#v", report.Metrics)
	}
	for _, category := range []string{"API1:2023", "API2:2023", "API3:2023", "API4:2023", "API5:2023", "API6:2023", "API7:2023", "API8:2023", "API9:2023", "API10:2023"} {
		if !hasOWASPCategory(report, category) {
			t.Errorf("missing OWASP category %s", category)
		}
	}
	if hasFinding(report, "PENTEST-IDOR-CANDIDATE") || hasFinding(report, "PENTEST-BUSINESS-FLOW") || hasFinding(report, "PENTEST-STATE-CHANGE-CANDIDATE") {
		t.Fatalf("heuristic-only candidates survived: %#v", report.Findings)
	}
	if report.Metrics.SuccessRate <= 0 || report.Metrics.ServerErrorRate <= 0 || report.Metrics.AuthenticationChallengeRate <= 0 {
		t.Fatalf("statistical metrics = %#v", report.Metrics)
	}
}

func TestRenderersEscapeEvidenceAndDiscloseEvidenceStandard(t *testing.T) {
	dataset := Dataset{Operations: []Operation{{Source: "https://api.example/<script>", Method: "GET", Status: 200, Target: "/users/1|admin"}}}
	report := Analyze(dataset, AnalyzeOptions{Title: "<script>alert(1)</script>", GeneratedAt: time.Unix(0, 0).UTC()})

	for _, format := range []string{"markdown", "html"} {
		var output bytes.Buffer
		if err := Write(report, format, &output, config.ColorNever); err != nil {
			t.Fatal(err)
		}
		rendered := output.String()
		if !strings.Contains(strings.ToLower(rendered), "evidence-backed") || !strings.Contains(strings.ToLower(rendered), "successful http status alone is not proof") {
			t.Fatalf("%s report omits evidence-standard disclosure", format)
		}
		if format == "html" && strings.Contains(rendered, "<script>alert(1)</script>") {
			t.Fatalf("HTML report contains unescaped title: %s", rendered)
		}
		if format == "markdown" && strings.Contains(rendered, "/users/1|admin") {
			t.Fatalf("Markdown report contains unescaped table delimiter: %s", rendered)
		}
	}
}

func TestHTMLReportRendersEscapedToggleableResponseProof(t *testing.T) {
	report := Report{
		Title:       "sj API Penetration Test Report",
		GeneratedAt: time.Unix(0, 0).UTC(),
		Methodology: reportMethodology,
		Findings: []Finding{{
			ID: "PENTEST-PROOF", Severity: SeverityHigh, Title: "Proof rendering",
			Count: 1, Confidence: "fixture", Evidence: []Evidence{{
				Source: "https://api.example/openapi.json", Method: "GET", Status: 200,
				Target: "/users/1", URL: "https://api.example/users/1", ContentType: "application/json",
				RequestBody: `{"userId":1}`, ResponseBody: `<script>alert("proof")</script>`, ResponseTruncated: true,
			}},
		}},
	}
	var output bytes.Buffer
	if err := Write(report, "html", &output, config.ColorNever); err != nil {
		t.Fatal(err)
	}
	rendered := output.String()
	for _, expected := range []string{"<details", "Response proof", "Response truncated", "&lt;script&gt;alert"} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("HTML proof missing %q: %s", expected, rendered)
		}
	}
	if strings.Contains(rendered, `<script>alert("proof")</script>`) {
		t.Fatalf("target response was embedded as executable HTML: %s", rendered)
	}
}

func TestAnalyzeSuppressesUnownedNumericIDORProbeFinding(t *testing.T) {
	dataset := Dataset{
		Operations: []Operation{
			{Origin: "fuzz", Method: "GET", Status: 200, URL: "https://api.example/users/1", Target: "/users/1", BaselineURL: "https://api.example/users/testvalue", Case: "idor_range:path:1:1", Identity: "alice", ResponseBody: `{"id":1}`},
			{Origin: "fuzz", Method: "GET", Status: 200, URL: "https://api.example/users/2", Target: "/users/2", BaselineURL: "https://api.example/users/testvalue", Case: "idor_range:path:1:2", Identity: "bob", ResponseBody: `{"id":2}`},
		},
		ImportedFindings: []ImportedFinding{{
			Severity: "high", Category: "idor_enumeration", Title: "Differential object responses",
			Method: "GET", URL: "https://api.example/users/testvalue", Evidence: "successful_ids=2", OWASP: []string{"API1:2023"},
		}},
	}
	report := Analyze(dataset, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC(), MaxEvidence: 5})
	if hasFinding(report, "idor_enumeration") {
		t.Fatalf("enumeration without ownership controls was promoted: %#v", report.Findings)
	}
}

func TestAnalyzeDoesNotCountFuzzProbesAsDistinctAPIOperations(t *testing.T) {
	operations := []Operation{{
		Origin: "automate", Source: "https://api.example/openapi.json", Method: "GET", Status: 200,
		Target: "/health", URL: "https://api.example/health",
	}}
	for identifier := 1; identifier <= 100; identifier++ {
		operations = append(operations, Operation{
			Origin: "fuzz", Source: "https://api.example", Method: "GET", Status: 200,
			Target: "/users/" + fmt.Sprint(identifier), URL: "https://api.example/users/" + fmt.Sprint(identifier),
			BaselineURL: "https://api.example/users/testvalue", Case: fmt.Sprintf("idor_range:path:1:%d", identifier),
			ResponseBody: fmt.Sprintf(`{"id":%d,"name":"test"}`, identifier),
		})
	}
	report := Analyze(Dataset{Operations: operations}, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	if report.Metrics.Operations != 1 || report.Metrics.ActiveProbes != 100 {
		t.Fatalf("operation/probe metrics = %#v", report.Metrics)
	}
	if hasFinding(report, "PENTEST-IDOR-CANDIDATE") {
		t.Fatalf("fuzz probes inflated passive IDOR findings: %#v", report.Findings)
	}
}

func TestAnalyzeDistinguishesHTTP200ApplicationFailureAndVerboseHint(t *testing.T) {
	operation := Operation{
		Origin: "automate", Source: "https://api.example/openapi.json", Method: "POST", Status: 200,
		Target: "/auth/password", URL: "https://api.example/auth/password", RequestBody: `{"CodeLogin":"S"}`,
		ResponseBody: `{"ok":false,"info":"the JSON object must be str, bytes or bytearray, not NoneType"}`,
	}
	report := Analyze(Dataset{Operations: []Operation{operation}}, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	if hasFinding(report, "PENTEST-STATE-CHANGE-CANDIDATE") {
		t.Fatalf("HTTP 200 failure envelope was classified as a successful state change: %#v", report.Findings)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("ambiguous NoneType failure was promoted: %#v", report.Findings)
	}
}

func TestAnalyzeHighlightsPersistentModificationAndSQLDisclosure(t *testing.T) {
	dataset := Dataset{Operations: []Operation{
		{
			Origin: "automate", Source: "https://api.example/openapi.json", Method: "POST",
			Status: 201, Target: "/entities", URL: "https://api.example/entities",
			RequestBody: `{"entity_id":"testvalue"}`, ResponseBody: `{"entity_id":"testvalue","created":true}`,
		},
		{
			Origin: "automate", Source: "https://api.example/openapi.json", Method: "GET",
			Status: 200, Target: "/entities/testvalue", URL: "https://api.example/entities/testvalue",
			ResponseBody: `{"entity_id":"testvalue","created":true}`,
		},
		{
			Origin: "automate", Source: "https://api.example/openapi.json", Method: "GET",
			Status: 500, Target: "/invoice_log/1", URL: "https://api.example/invoice_log/1",
			ResponseBody: `(pyodbc.ProgrammingError) SQL Server invalid object name dbo.invoice_log via SQLAlchemy stored procedure spGetInvoice`,
		},
	}}
	report := Analyze(dataset, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC(), MaxEvidence: 5})
	if !hasFinding(report, "PENTEST-PERSISTENT-UNAUTH-WRITE") {
		t.Fatalf("persistent modification finding missing: %#v", report.Findings)
	}
	if !hasFinding(report, "PENTEST-VERBOSE-BACKEND-DISCLOSURE") {
		t.Fatalf("verbose SQL disclosure finding missing: %#v", report.Findings)
	}
}

func TestAnalyzeDoesNotTreatFailureEnvelopeAsPersistentModification(t *testing.T) {
	dataset := Dataset{Operations: []Operation{
		{
			Origin: "automate", Source: "https://api.example/openapi.json", Method: "POST",
			Status: 200, Target: "/entities", URL: "https://api.example/entities",
			ResponseBody: `{"ok":false,"error":"validation failed"}`,
		},
		{
			Origin: "automate", Source: "https://api.example/openapi.json", Method: "GET",
			Status: 200, Target: "/entities/testvalue", URL: "https://api.example/entities/testvalue",
			ResponseBody: `{"name":"testvalue"}`,
		},
	}}
	report := Analyze(dataset, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	if hasFinding(report, "PENTEST-PERSISTENT-UNAUTH-WRITE") {
		t.Fatalf("failure envelope produced persistent modification finding: %#v", report.Findings)
	}
}

func TestHTMLSuppressesResponseGuidedSuccessNoise(t *testing.T) {
	dataset := Dataset{
		Operations: []Operation{{
			Origin: "fuzz", Method: "GET", Status: 200, URL: "https://api.example/tenant?tenantId=1", Target: "/tenant",
			BaselineURL: "https://api.example/tenant", Case: "response_guided:1:query.tenantId",
			Guidance: "applied <bounded> repair", ResponseBody: `{"id":1,"name":"tenant"}`,
		}},
		ImportedFindings: []ImportedFinding{{
			Severity: "medium", Category: "response_guided_success", Title: "Guided success",
			Method: "GET", URL: "https://api.example/tenant?tenantId=1", Evidence: "repair succeeded",
		}},
	}
	report := Analyze(dataset, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	var output bytes.Buffer
	if err := Write(report, "html", &output, config.ColorNever); err != nil {
		t.Fatal(err)
	}
	rendered := output.String()
	if strings.Contains(rendered, "Guided success") || strings.Contains(rendered, "Response-guided analysis") {
		t.Fatalf("response-guided coverage signal survived as a finding: %s", rendered)
	}
}

func TestAnalyzeDiscardsImportedPaymentCardFalsePositiveWhenProofIsCaptured(t *testing.T) {
	const targetURL = "https://api.example/customer/1492030000000000"
	base := Dataset{
		Operations: []Operation{{
			Origin: "fuzz", Method: "GET", Status: 200, URL: targetURL, Target: "/customer/1492030000000000",
			ResponseBody: `{"id":"1492030000000000","contact":"public@example.test"}`,
		}},
		ImportedFindings: []ImportedFinding{{
			Severity: "high", Category: "pii_exposure", Title: "Potential PII exposed in API response",
			Method: "GET", URL: targetURL, Evidence: "matched_types=payment card candidate; matched values redacted",
		}},
	}
	if report := Analyze(base, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()}); hasFinding(report, "pii_exposure") || hasFinding(report, "PENTEST-SENSITIVE-DATA-EXPOSURE") {
		t.Fatalf("long identifier survived payment-card revalidation: %#v", report.Findings)
	}

	base.Operations[0].ResponseBody = `{"card":"4111111111111111"}`
	if report := Analyze(base, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()}); !hasFinding(report, "PENTEST-SENSITIVE-DATA-EXPOSURE") {
		t.Fatalf("valid payment-card candidate was discarded: %#v", report.Findings)
	}
}

func TestAnalyzeSuppressesImportedPIICandidateWithoutCapturedProof(t *testing.T) {
	report := Analyze(Dataset{ImportedFindings: []ImportedFinding{{
		Severity: "high", Category: "pii_exposure", Title: "Potential PII exposed in API response",
		Method: "GET", URL: "https://api.example/customer/1", Evidence: "matched values redacted",
	}}}, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	if hasFinding(report, "pii_exposure") {
		t.Fatalf("candidate without captured proof survived: %#v", report.Findings)
	}
}

func TestAnalyzeSuppressesImportedVerboseFindingInFavorOfRetainedBodyAnalysis(t *testing.T) {
	report := Analyze(Dataset{ImportedFindings: []ImportedFinding{{
		Severity: "medium", Category: "verbose_error", Title: "Verbose implementation details",
		Method: "GET", URL: "https://api.example/failure", Evidence: "matched_types=stack_trace",
	}}}, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	if len(report.Findings) != 0 {
		t.Fatalf("type-only imported disclosure survived without retained proof: %#v", report.Findings)
	}
}

func TestTerminalReportHonorsForcedColorModes(t *testing.T) {
	report := Analyze(Dataset{Operations: []Operation{{Method: "GET", Status: 500, Target: "/error"}}}, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	var colored bytes.Buffer
	if err := Write(report, "terminal", &colored, config.ColorAlways); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(colored.String(), "\x1b[") {
		t.Fatalf("forced terminal report has no ANSI colors: %q", colored.String())
	}
	var plain bytes.Buffer
	if err := Write(report, "terminal", &plain, config.ColorNever); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain.String(), "\x1b[") {
		t.Fatalf("plain terminal report contains ANSI colors: %q", plain.String())
	}
}

func writeReportFixture(t *testing.T, directory, name, content string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func hasFinding(report Report, id string) bool {
	for _, finding := range report.Findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}

func hasOWASPCategory(report Report, id string) bool {
	for _, category := range report.OWASP {
		if category.ID == id {
			return true
		}
	}
	return false
}
