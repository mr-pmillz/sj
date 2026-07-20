package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreMigratesAndPersistsTypedRunResults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sj.db")
	resultStore, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resultStore.Close() })

	run, err := resultStore.BeginRun(t.Context(), "automate", map[string]any{"source_count": 1})
	if err != nil {
		t.Fatal(err)
	}
	observations := []Observation{{
		Kind: "automate", Source: "https://api.example/openapi.json", Method: "GET",
		URL: "https://api.example/users/1", Path: "/users/1", Status: 200,
		ContentType: "application/json", RequestBody: []byte(`{"id":1}`),
		ResponseBody: []byte(`{"email":"redacted@example.test"}`), ResponseTruncated: true,
	}}
	if err := resultStore.AddObservations(t.Context(), run.ID, observations); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddFindings(t.Context(), run.ID, []Finding{{
		Severity: "high", Category: "API1:2023", Title: "Object authorization candidate",
		Method: "GET", URL: "https://api.example/users/1", Evidence: map[string]any{"identity": "user"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.FinishRun(t.Context(), run.ID, RunSucceeded, ""); err != nil {
		t.Fatal(err)
	}

	got, err := resultStore.Observations(t.Context(), Query{RunIDs: []string{run.ID}, Kinds: []string{"automate"}, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got[0].ResponseBody) != string(observations[0].ResponseBody) || !got[0].ResponseTruncated {
		t.Fatalf("observations = %#v", got)
	}
	findings, err := resultStore.Findings(t.Context(), Query{RunIDs: []string{run.ID}, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Category != "API1:2023" {
		t.Fatalf("findings = %#v", findings)
	}
	runs, err := resultStore.ListRuns(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].Status != RunSucceeded || runs[0].Command != "automate" {
		t.Fatalf("runs = %#v", runs)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("database permissions = %o, want private", info.Mode().Perm())
	}
}

func TestAddObservationsRejectsInvalidBatchWithoutPartialCommit(t *testing.T) {
	resultStore, err := Open(t.Context(), filepath.Join(t.TempDir(), "sj.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resultStore.Close() })
	run, err := resultStore.BeginRun(t.Context(), "brute", nil)
	if err != nil {
		t.Fatal(err)
	}
	err = resultStore.AddObservations(t.Context(), run.ID, []Observation{
		{Kind: "brute_spec", URL: "https://api.example/openapi.json", Status: 200},
		{Kind: "", URL: "https://api.example/invalid", Status: 200},
	})
	if err == nil {
		t.Fatal("invalid observation batch was accepted")
	}
	got, queryErr := resultStore.Observations(context.Background(), Query{RunIDs: []string{run.ID}, Limit: 10})
	if queryErr != nil {
		t.Fatal(queryErr)
	}
	if len(got) != 0 {
		t.Fatalf("partial batch committed: %#v", got)
	}
}

func TestFinishRunIsIdempotentButRejectsTerminalRewrite(t *testing.T) {
	resultStore, err := Open(t.Context(), filepath.Join(t.TempDir(), "sj.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resultStore.Close() })
	run, err := resultStore.BeginRun(t.Context(), "report", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := resultStore.FinishRun(t.Context(), run.ID, RunFailed, "render failed"); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.FinishRun(t.Context(), run.ID, RunFailed, "render failed"); err != nil {
		t.Fatalf("idempotent finish failed: %v", err)
	}
	if err := resultStore.FinishRun(t.Context(), run.ID, RunSucceeded, ""); err == nil {
		t.Fatal("terminal run status was rewritten")
	}
}

func TestCompletedRunSurvivesDatabaseReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sj.db")
	resultStore, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	run, err := resultStore.BeginRun(t.Context(), "fuzz", map[string]any{"max_requests": 10})
	if err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddObservations(t.Context(), run.ID, []Observation{{Kind: "fuzz_probe", Method: "GET", URL: "https://api.example/items", Status: 200}}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.FinishRun(t.Context(), run.ID, RunSucceeded, ""); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	observations, err := reopened.Observations(t.Context(), Query{RunIDs: []string{run.ID}, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	runs, err := reopened.ListRuns(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 || len(runs) != 1 || runs[0].Status != RunSucceeded {
		t.Fatalf("observations=%#v runs=%#v", observations, runs)
	}
}

func TestSQLiteFilesRemainPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sj.db")
	resultStore, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resultStore.Close() })
	if _, err := resultStore.BeginRun(t.Context(), "audit", nil); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		info, statErr := os.Stat(candidate)
		if os.IsNotExist(statErr) {
			continue
		}
		if statErr != nil {
			t.Fatal(statErr)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("SQLite file %s permissions = %o, want private", filepath.Base(candidate), info.Mode().Perm())
		}
	}
}

func TestOpenRejectsSymlinkDatabaseTarget(t *testing.T) {
	directory := t.TempDir()
	actual := filepath.Join(directory, "actual.db")
	if err := os.WriteFile(actual, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "results.db")
	if err := os.Symlink(actual, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), link); err == nil {
		t.Fatal("symlink result database target was accepted")
	}
	content, err := os.ReadFile(actual)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "do not replace" {
		t.Fatalf("symlink target was modified: %q", content)
	}
}

func TestMemoryStoresAreIsolated(t *testing.T) {
	first, err := Open(t.Context(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := Open(t.Context(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	if _, err := first.BeginRun(t.Context(), "brute", nil); err != nil {
		t.Fatal(err)
	}
	runs, err := second.ListRuns(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 0 {
		t.Fatalf("independent memory store observed runs: %#v", runs)
	}
}
