package mcpserver

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/store"
)

func TestAnalyzeAPIResultsRequiresRootConfinedInput(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	insidePath := writeAnalysisFixture(t, root, "inside.json")
	outsidePath := writeAnalysisFixture(t, outside, "outside.json")
	session := connectTestClient(t, Options{
		Version: "test", AllowLocalFiles: true, AssessmentRoots: []string{root},
	})

	missing := callTool(t, session, "analyze_api_results", nil)
	if !missing.IsError || !strings.Contains(toolText(missing), "at least one") {
		t.Fatalf("missing input = isError:%v text:%q", missing.IsError, toolText(missing))
	}
	outOfRoot := callTool(t, session, "analyze_api_results", map[string]any{
		"input_paths": []any{outsidePath},
	})
	if !outOfRoot.IsError || !strings.Contains(toolText(outOfRoot), "outside") {
		t.Fatalf("out-of-root input = isError:%v text:%q", outOfRoot.IsError, toolText(outOfRoot))
	}
	relative := callTool(t, session, "analyze_api_results", map[string]any{
		"input_paths": []any{filepath.Base(insidePath)},
	})
	if !relative.IsError || !strings.Contains(toolText(relative), "absolute path") {
		t.Fatalf("relative input = isError:%v text:%q", relative.IsError, toolText(relative))
	}
}

func TestAnalyzeAPIResultsRejectsExplicitSymlinkInput(t *testing.T) {
	root := t.TempDir()
	target := writeAnalysisFixture(t, root, "target.json")
	link := filepath.Join(root, "results-link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	session := connectTestClient(t, Options{
		Version: "test", AssessmentRoots: []string{root}, MaxResults: 20,
	})
	result := callTool(t, session, "analyze_api_results", map[string]any{
		"input_paths": []any{link},
	})
	if !result.IsError || !strings.Contains(strings.ToLower(toolText(result)), "symlink") {
		t.Fatalf("symlink input = isError:%v text:%q", result.IsError, toolText(result))
	}
}

func TestAnalyzeAPIResultsRendersLegacyInputsThroughReportPipeline(t *testing.T) {
	root := t.TempDir()
	inputPath := writeAnalysisFixture(t, root, "results.json")
	session := connectTestClient(t, Options{
		Version: "test", AssessmentRoots: []string{root}, MaxResults: 20,
	})

	result := callTool(t, session, "analyze_api_results", map[string]any{
		"input_paths":   []any{inputPath},
		"output_format": "html",
		"title":         "Stored Evidence Analysis",
		"max_evidence":  2,
	})
	if result.IsError {
		t.Fatalf("analysis failed: %s", toolText(result))
	}
	var output analyzeAPIResultsOutput
	decodeStructured(t, result, &output)
	if output.ContentType != "text/html; charset=utf-8" || output.Encoding != "utf-8" {
		t.Fatalf("output metadata = %#v", output)
	}
	for _, fragment := range []string{"Stored Evidence Analysis", "GET", "https://api.example.test/widgets/7"} {
		if !strings.Contains(output.Content, fragment) {
			t.Fatalf("HTML output does not contain %q", fragment)
		}
	}
}

func TestAnalyzeAPIResultsReadsOnlyConfiguredLegacyRuns(t *testing.T) {
	root := t.TempDir()
	databasePath := filepath.Join(root, "results.db")
	resultStore, err := store.Open(t.Context(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	run, err := resultStore.BeginRun(t.Context(), "automate", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddObservations(t.Context(), run.ID, []store.Observation{{
		Kind: "automate", Source: "https://api.example.test/openapi.json", Method: "GET",
		URL: "https://api.example.test/accounts/7", Path: "/accounts/7", Status: 500,
		ContentType: "application/json", ResponseBody: []byte(`{"error":"pyodbc SQL Server invalid object name accounts"}`),
	}}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.FinishRun(t.Context(), run.ID, store.RunSucceeded, ""); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(databasePath)
	if err != nil {
		t.Fatal(err)
	}

	base := config.New()
	base.DatabasePath = databasePath
	session := connectTestClient(t, Options{
		Config: base, Version: "test", AssessmentRoots: []string{root}, MaxResults: 20,
	})
	result := callTool(t, session, "analyze_api_results", map[string]any{
		"run_ids":       []any{run.ID},
		"output_format": "markdown",
	})
	if result.IsError {
		t.Fatalf("run analysis failed: %s", toolText(result))
	}
	var output analyzeAPIResultsOutput
	decodeStructured(t, result, &output)
	if output.ContentType != "text/markdown; charset=utf-8" || !strings.Contains(output.Content, "/accounts/7") {
		t.Fatalf("unexpected output: %#v", output)
	}
	after, err := os.Stat(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() {
		t.Fatalf("read-only analysis changed configured database: before=%v/%d after=%v/%d", before.ModTime(), before.Size(), after.ModTime(), after.Size())
	}

	unknown := callTool(t, session, "analyze_api_results", map[string]any{
		"run_ids": []any{"not-a-real-run"},
	})
	if !unknown.IsError || !strings.Contains(toolText(unknown), "no stored results") {
		t.Fatalf("unknown run = isError:%v text:%q", unknown.IsError, toolText(unknown))
	}
}

func TestOpenSQLiteReadOnlyRejectsWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.db")
	resultStore, err := store.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := resultStore.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := openSQLiteReadOnly(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(t.Context(), `CREATE TABLE should_not_exist (id INTEGER)`); err == nil {
		t.Fatal("read-only result database accepted a write")
	}
}

func TestEnforceLegacyResultByteBudget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.db")
	resultStore, err := store.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	run, err := resultStore.BeginRun(t.Context(), "automate", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddObservations(t.Context(), run.ID, []store.Observation{{
		Kind: "automate", Method: "GET", URL: "https://api.example.test/items/1",
		RequestBody: []byte(strings.Repeat("r", 48)), ResponseBody: []byte(strings.Repeat("s", 48)),
	}}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddFindings(t.Context(), run.ID, []store.Finding{{
		Severity: "medium", Category: "verbose_error", Title: "bounded evidence",
		Evidence: map[string]any{"payload": strings.Repeat("e", 1024)},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := openSQLiteReadOnly(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	tx, err := db.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := enforceLegacyResultByteBudget(t.Context(), tx, []string{run.ID}, 512); err == nil || !strings.Contains(err.Error(), "512-byte") {
		t.Fatalf("oversized stored results were accepted: %v", err)
	}
	if err := enforceLegacyResultByteBudget(t.Context(), tx, []string{run.ID}, 4096); err != nil {
		t.Fatalf("bounded stored results were rejected: %v", err)
	}
}

func TestAnalyzeAPIResultsValidatesFormatEvidenceAndOutputBounds(t *testing.T) {
	root := t.TempDir()
	inputPath := writeAnalysisFixture(t, root, "results.json")
	session := connectTestClient(t, Options{
		Version: "test", AssessmentRoots: []string{root}, MaxResults: 5, MaxOutputBytes: 512,
	})

	for name, arguments := range map[string]map[string]any{
		"format":   {"input_paths": []any{inputPath}, "output_format": "json"},
		"evidence": {"input_paths": []any{inputPath}, "max_evidence": 6},
	} {
		t.Run(name, func(t *testing.T) {
			result := callTool(t, session, "analyze_api_results", arguments)
			if !result.IsError {
				t.Fatalf("invalid request unexpectedly succeeded: %s", toolText(result))
			}
		})
	}

	tooLarge := callTool(t, session, "analyze_api_results", map[string]any{
		"input_paths": []any{inputPath}, "output_format": "html",
	})
	if !tooLarge.IsError || !strings.Contains(toolText(tooLarge), "output exceeds") {
		t.Fatalf("oversized output = isError:%v text:%q", tooLarge.IsError, toolText(tooLarge))
	}
}

func writeAnalysisFixture(t *testing.T, directory, name string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	data, err := json.Marshal(map[string]any{"results": []map[string]any{{
		"source": "https://api.example.test/openapi.json", "method": "GET", "status": 200,
		"target": "/widgets/7", "url": "https://api.example.test/widgets/7",
		"content_type": "application/json", "response_body": `{"error":"pyodbc SQL Server invalid object name widgets"}`,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
