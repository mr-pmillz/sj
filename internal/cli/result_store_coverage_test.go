package cli

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/mr-pmillz/sj/pkg/audit"
	"github.com/mr-pmillz/sj/pkg/brute"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/fuzz"
	"github.com/mr-pmillz/sj/pkg/output"
	pentestreport "github.com/mr-pmillz/sj/pkg/report"
	"github.com/mr-pmillz/sj/pkg/store"
)

func TestResultRunPersistsEveryCLIResultKind(t *testing.T) {
	t.Parallel()

	databasePath := filepath.Join(t.TempDir(), "results.db")
	resultStore, err := store.Open(t.Context(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resultStore.Close() })
	storedRun, err := resultStore.BeginRun(t.Context(), "coverage", map[string]any{"test": true})
	if err != nil {
		t.Fatal(err)
	}
	run := &resultRun{store: resultStore, run: storedRun}

	if err := run.addBruteReports(t.Context(), []brute.Report{{
		Target:      "https://api.example.test",
		SpecsFound:  []brute.SpecResult{{URL: "https://api.example.test/openapi.json", ContentType: "application/json", OpenAPIVersion: "3.1.0", Title: "API", Description: "contract"}},
		Interesting: []brute.Interesting{{URL: "https://api.example.test/admin", StatusCode: 403, ContentType: "application/json"}},
		Summary:     brute.Summary{URLsTested: 3, SpecsFoundCount: 1},
	}}); err != nil {
		t.Fatal(err)
	}

	cfg := config.New()
	cfg.LocalFile = "/tmp/openapi.yaml"
	cfg.APITarget = "https://api.example.test/base/"
	writer := output.NewWriter(cfg)
	writer.EndpointPaths = []string{"/users/{id}", "health"}
	writer.PreparedRequests = []output.PreparedRequest{{Method: "GET", URL: "https://api.example.test/users/1", Path: "/users/{id}", Body: []byte(`{"id":1}`)}}
	if err := run.addEndpointResults(t.Context(), cfg, writer); err != nil {
		t.Fatal(err)
	}
	if err := run.addPreparedRequests(t.Context(), cfg, writer); err != nil {
		t.Fatal(err)
	}

	auditReport := audit.Report{
		OpenAPIVersion: "3.1.0", Title: "API", Summary: audit.Summary{Operations: 2},
		Findings: []audit.Finding{{ID: "AUTH001", Severity: audit.SeverityHigh, Title: "Missing authorization", Location: "/users/{id}", Description: "object access is unspecified", Recommendation: "declare authorization"}},
	}
	if err := run.addAuditReport(t.Context(), cfg, auditReport); err != nil {
		t.Fatal(err)
	}
	if err := run.addArtifact(t.Context(), "converted_spec", cfg.LocalFile, "/tmp/openapi.json", map[string]any{"format": "json"}); err != nil {
		t.Fatal(err)
	}

	pentest := pentestreport.Report{
		Title: "Assessment", Methodology: "bounded",
		Findings: []pentestreport.Finding{
			{ID: "BOLA001", Severity: pentestreport.SeverityHigh, Title: "Object candidate", OWASP: []string{"API1"}, Evidence: []pentestreport.Evidence{{Source: "fuzz.json", Method: "GET", Status: 200, Target: "https://api.example.test/users/2", Note: "ownership control"}}},
			{ID: "INFO001", Severity: pentestreport.SeverityInformational, Title: "Coverage gap", OWASP: []string{"API9"}},
		},
	}
	if err := run.addPentestReport(t.Context(), pentest); err != nil {
		t.Fatal(err)
	}
	remaining := 4
	fuzzReport := fuzz.Report{
		Summary: fuzz.Summary{Requests: 1, Responses2xx: 1},
		Probes: []fuzz.ProbeResult{{
			Method: "GET", URL: "https://api.example.test/users/2", BaselineURL: "https://api.example.test/users/1",
			Case: "foreign-object", Category: "idor", Identity: "alice", ContentType: "application/json", Status: 200,
			RequestBody: `{"id":2}`, ResponseBytes: 24, ResponseHash: "sha256:abc", ResponseBody: `{"id":2}`,
			ResponseTruncated: true, RateLimitRemaining: &remaining, PIITypes: []string{"email"}, VerboseError: true,
			Error: "", DurationMillis: 5, Guidance: "compare ownership",
		}},
		Findings: []fuzz.Finding{{Severity: "medium", Category: "idor-candidate", Title: "Foreign object returned", Method: "GET", URL: "https://api.example.test/users/2", Evidence: "distinct body", OWASP: []string{"API1"}}},
	}
	if err := run.addFuzzReport(t.Context(), fuzzReport); err != nil {
		t.Fatal(err)
	}

	observations, err := resultStore.Observations(t.Context(), store.Query{RunIDs: []string{storedRun.ID}, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	kinds := make(map[string]int)
	for _, observation := range observations {
		kinds[observation.Kind]++
	}
	for _, kind := range []string{"brute_summary", "brute_spec", "brute_interesting", "endpoint", "prepared_request", "audit_summary", "converted_spec", "report_summary", "fuzz_summary", "fuzz_probe"} {
		if kinds[kind] == 0 {
			t.Errorf("missing persisted observation kind %q: %#v", kind, kinds)
		}
	}
	findings, err := resultStore.Findings(t.Context(), store.Query{RunIDs: []string{storedRun.ID}, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 4 {
		t.Fatalf("persisted findings = %#v, want audit + two report + fuzz", findings)
	}
}

func TestResultRunNilAndNoDatabasePathsAreNoOps(t *testing.T) {
	t.Parallel()

	noDatabase := config.New()
	noDatabase.NoDatabase = true
	if run, err := beginResultRun(t.Context(), noDatabase, "test", nil); err != nil || run != nil {
		t.Fatalf("beginResultRun(no database) = %#v, %v", run, err)
	}
	emptyPath := config.New()
	emptyPath.DatabasePath = ""
	if run, err := beginResultRun(t.Context(), emptyPath, "test", nil); err != nil || run != nil {
		t.Fatalf("beginResultRun(empty path) = %#v, %v", run, err)
	}

	var run *resultRun
	if err := run.finish(nil); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(run.finish(context.Canceled), context.Canceled) {
		t.Fatal("nil result run did not preserve cancellation")
	}
	if err := run.addAutomateResults(t.Context(), output.NewWriter(config.New()), nil); err != nil {
		t.Fatal(err)
	}
	if err := run.addBruteReports(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if err := run.addEndpointResults(t.Context(), config.New(), output.NewWriter(config.New())); err != nil {
		t.Fatal(err)
	}
	if err := run.addPreparedRequests(t.Context(), config.New(), output.NewWriter(config.New())); err != nil {
		t.Fatal(err)
	}
	if err := run.addAuditReport(t.Context(), config.New(), audit.Report{}); err != nil {
		t.Fatal(err)
	}
	if err := run.addArtifact(t.Context(), "kind", "source", "path", nil); err != nil {
		t.Fatal(err)
	}
	if err := run.addPentestReport(t.Context(), pentestreport.Report{}); err != nil {
		t.Fatal(err)
	}
	if err := run.addFuzzReport(t.Context(), fuzz.Report{}); err != nil {
		t.Fatal(err)
	}
	if got := specificationSource(&config.Config{SwaggerURL: "https://api.example/spec", LocalFile: "ignored"}); got != "https://api.example/spec" {
		t.Fatalf("remote source = %q", got)
	}
	if got := specificationSource(&config.Config{LocalFile: "spec.yaml"}); got != "spec.yaml" {
		t.Fatalf("local source = %q", got)
	}
}

func TestRequestAuthContextClassifiesWithoutRetainingValues(t *testing.T) {
	for _, test := range []struct {
		name    string
		headers []string
		want    string
	}{
		{name: "none", want: "anonymous"},
		{name: "non credential", headers: []string{"Accept-Language: en"}, want: "anonymous"},
		{name: "authorization", headers: []string{"Authorization: Bearer never-persist-this"}, want: "authenticated"},
		{name: "api key", headers: []string{"X-API-Key: never-persist-this"}, want: "authenticated"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := requestAuthContext(test.headers); got != test.want {
				t.Fatalf("requestAuthContext() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestResultRunFinishPersistsCanceledAndFailedStatuses(t *testing.T) {
	t.Parallel()

	for name, commandErr := range map[string]error{
		"canceled": context.Canceled,
		"failed":   errors.New("stage failed"),
	} {
		t.Run(name, func(t *testing.T) {
			databasePath := filepath.Join(t.TempDir(), "results.db")
			cfg := config.New()
			cfg.DatabasePath = databasePath
			run, err := beginResultRun(t.Context(), cfg, "coverage", nil)
			if err != nil {
				t.Fatal(err)
			}
			runID := run.run.ID
			if err := run.finish(commandErr); !errors.Is(err, commandErr) {
				t.Fatalf("finish() error = %v, want %v", err, commandErr)
			}
			reopened, err := store.Open(t.Context(), databasePath)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = reopened.Close() })
			runs, err := reopened.ListRuns(t.Context(), 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(runs) != 1 || runs[0].ID != runID {
				t.Fatalf("runs = %#v", runs)
			}
			wantStatus := store.RunFailed
			if errors.Is(commandErr, context.Canceled) {
				wantStatus = store.RunCanceled
			}
			if runs[0].Status != wantStatus || runs[0].Message != commandErr.Error() {
				t.Fatalf("terminal run = %#v, want status %s", runs[0], wantStatus)
			}
		})
	}
}
