package report

import (
	"bytes"
	"fmt"
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
	writeReportFixture(t, directory, "automate.json", `{"results":[{"source":"https://api.example/openapi.json","method":"GET","status":200,"target":"/users/1"},{"source":"https://api.example/openapi.json","method":"DELETE","status":204,"target":"/users/1"}]}`)
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
	if len(dataset.Operations) != 2 || len(dataset.Discoveries) != 1 || len(dataset.Targets) != 1 || len(dataset.Failures) != 1 {
		t.Fatalf("dataset = %#v", dataset)
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
	path := writeReportFixture(t, directory, "brute.json", `{"target":"https://api.example","specs_found":[],"summary":{"urls_tested":3,"responses_4xx":3,"waf_challenge_detected":true,"waf_challenge_responses":3,"references_rejected":2,"references_skipped":4}}`)
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
		"References rejected by policy: **2**", "References skipped by limits: **4**",
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

func TestAnalyzeCreatesWeightedAPIPenetrationTestCandidates(t *testing.T) {
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

	if report.Severity.Critical.Observations == 0 || report.Severity.High.Observations == 0 || report.Severity.Medium.Observations == 0 {
		t.Fatalf("severity summary = %#v", report.Severity)
	}
	if report.Severity.WeightedPoints == 0 {
		t.Fatal("weighted severity points were not calculated")
	}
	for _, category := range []string{"API1:2023", "API2:2023", "API3:2023", "API4:2023", "API5:2023", "API6:2023", "API7:2023", "API8:2023", "API9:2023", "API10:2023"} {
		if !hasOWASPCategory(report, category) {
			t.Errorf("missing OWASP category %s", category)
		}
	}
	if !hasFinding(report, "PENTEST-IDOR-CANDIDATE") || !hasFinding(report, "PENTEST-BUSINESS-FLOW") {
		t.Fatalf("expected IDOR and business-logic candidates: %#v", report.Findings)
	}
	if report.Metrics.SuccessRate <= 0 || report.Metrics.ServerErrorRate <= 0 || report.Metrics.AuthenticationChallengeRate <= 0 {
		t.Fatalf("statistical metrics = %#v", report.Metrics)
	}
}

func TestRenderersEscapeEvidenceAndDiscloseHeuristicLimits(t *testing.T) {
	dataset := Dataset{Operations: []Operation{{Source: "https://api.example/<script>", Method: "GET", Status: 200, Target: "/users/1|admin"}}}
	report := Analyze(dataset, AnalyzeOptions{Title: "<script>alert(1)</script>", GeneratedAt: time.Unix(0, 0).UTC()})

	for _, format := range []string{"markdown", "html"} {
		var output bytes.Buffer
		if err := Write(report, format, &output, config.ColorNever); err != nil {
			t.Fatal(err)
		}
		rendered := output.String()
		if !strings.Contains(strings.ToLower(rendered), "candidate") || !strings.Contains(strings.ToLower(rendered), "not confirmed") {
			t.Fatalf("%s report omits heuristic disclosure", format)
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
	dataset := Dataset{Operations: []Operation{{
		Source: "https://api.example/openapi.json", Method: "GET", Status: 200,
		Target: "/users/1", URL: "https://api.example/users/1", ContentType: "application/json",
		RequestBody: `{"userId":1}`, ResponseBody: `<script>alert("proof")</script>`, ResponseTruncated: true,
	}}}
	report := Analyze(dataset, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC(), MaxEvidence: 5})
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

func TestAnalyzeAttachesNumericIDORProbeProofToImportedFinding(t *testing.T) {
	dataset := Dataset{
		Operations: []Operation{
			{Origin: "fuzz", Method: "GET", Status: 200, URL: "https://api.example/users/1", Target: "/users/1", BaselineURL: "https://api.example/users/testvalue", Case: "idor_range:path:1:1", Identity: "alice", ResponseBody: `{"id":1}`},
			{Origin: "fuzz", Method: "GET", Status: 200, URL: "https://api.example/users/2", Target: "/users/2", BaselineURL: "https://api.example/users/testvalue", Case: "idor_range:path:1:2", Identity: "alice", ResponseBody: `{"id":2}`},
		},
		ImportedFindings: []ImportedFinding{{
			Severity: "high", Category: "idor_enumeration", Title: "Differential object responses",
			Method: "GET", URL: "https://api.example/users/testvalue", Evidence: "successful_ids=2", OWASP: []string{"API1:2023"},
		}},
	}
	report := Analyze(dataset, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC(), MaxEvidence: 5})
	for _, finding := range report.Findings {
		if finding.ID != "idor_enumeration" {
			continue
		}
		if len(finding.Evidence) < 3 || finding.Evidence[1].ResponseBody == "" || finding.Evidence[2].ResponseBody == "" {
			t.Fatalf("IDOR finding did not retain probe proof: %#v", finding.Evidence)
		}
		return
	}
	t.Fatalf("imported IDOR finding missing: %#v", report.Findings)
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
	if !hasFinding(report, "PENTEST-APPLICATION-FAILURE") || !hasFinding(report, "PENTEST-VERBOSE-ERROR") {
		t.Fatalf("application failure evidence missing: %#v", report.Findings)
	}
}

func TestHTMLProofIncludesEscapedResponseGuidance(t *testing.T) {
	dataset := Dataset{
		Operations: []Operation{{
			Origin: "fuzz", Method: "GET", Status: 200, URL: "https://api.example/tenant?tenantId=1", Target: "/tenant",
			BaselineURL: "https://api.example/tenant", Case: "response_guided:1:query.tenantId",
			Guidance: "applied <bounded> repair", ResponseBody: `{"id":1,"name":"tenant"}`,
		}},
		ImportedFindings: []ImportedFinding{{
			Severity: "informational", Category: "response_guided_success", Title: "Guided success",
			Method: "GET", URL: "https://api.example/tenant?tenantId=1", Evidence: "repair succeeded",
		}},
	}
	report := Analyze(dataset, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	var output bytes.Buffer
	if err := Write(report, "html", &output, config.ColorNever); err != nil {
		t.Fatal(err)
	}
	rendered := output.String()
	if !strings.Contains(rendered, "Response-guided analysis") || !strings.Contains(rendered, "applied &lt;bounded&gt; repair") {
		t.Fatalf("guided proof missing or unescaped: %s", rendered)
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
	if report := Analyze(base, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()}); hasFinding(report, "pii_exposure") {
		t.Fatalf("long identifier survived payment-card revalidation: %#v", report.Findings)
	}

	base.Operations[0].ResponseBody = `{"card":"4111111111111111"}`
	if report := Analyze(base, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()}); !hasFinding(report, "pii_exposure") {
		t.Fatalf("valid payment-card candidate was discarded: %#v", report.Findings)
	}
}

func TestAnalyzePreservesImportedPIICandidateWithoutCapturedProof(t *testing.T) {
	report := Analyze(Dataset{ImportedFindings: []ImportedFinding{{
		Severity: "high", Category: "pii_exposure", Title: "Potential PII exposed in API response",
		Method: "GET", URL: "https://api.example/customer/1", Evidence: "matched values redacted",
	}}}, AnalyzeOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	if !hasFinding(report, "pii_exposure") {
		t.Fatalf("candidate without captured proof was incorrectly disproved: %#v", report.Findings)
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
