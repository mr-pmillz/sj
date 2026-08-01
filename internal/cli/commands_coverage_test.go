package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/store"
	"github.com/spf13/cobra"
)

func TestSafeLocalCLICommandsExerciseCompletePipelines(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "test_spec_v2.yaml")

	t.Run("convert", func(t *testing.T) {
		cfg := localCommandConfig(fixture)
		cfg.OutputFormat = "json"
		cfg.Outfile = filepath.Join(t.TempDir(), "openapi.json")
		if err := runConvert(t.Context(), cfg); err != nil {
			t.Fatal(err)
		}
		converted, err := os.ReadFile(cfg.Outfile)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(converted, []byte("openapi:")) {
			t.Fatalf("converted output is not OpenAPI 3 YAML: %.120s", converted)
		}
	})

	t.Run("endpoints", func(t *testing.T) {
		cfg := localCommandConfig(fixture)
		cfg.APITarget = "https://api.example.test"
		if err := runEndpoints(t.Context(), cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.Mode != config.ModeEndpoints {
			t.Fatalf("mode = %v", cfg.Mode)
		}
	})

	t.Run("prepare curl", func(t *testing.T) {
		cfg := localCommandConfig(fixture)
		cfg.APITarget = "https://api.example.test"
		cfg.PrepareFor = "curl"
		if err := runPrepare(t.Context(), cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.Mode != config.ModePrepare {
			t.Fatalf("mode = %v", cfg.Mode)
		}
	})

	t.Run("audit JSON", func(t *testing.T) {
		cfg := localCommandConfig(fixture)
		cfg.Outfile = filepath.Join(t.TempDir(), "audit.json")
		if err := runAudit(t.Context(), cfg, "json", "none"); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(cfg.Outfile)
		if err != nil || !bytes.Contains(data, []byte(`"findings"`)) {
			t.Fatalf("audit output = %.120s, %v", data, err)
		}
	})
}

func TestSafeCLICommandsRejectInvalidInputBeforeSideEffects(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "test_spec_v2.yaml")

	prepare := localCommandConfig(fixture)
	prepare.CustomDate = "07/30/2026"
	if err := runPrepare(t.Context(), prepare); err == nil || !strings.Contains(err.Error(), "custom-date") {
		t.Fatalf("invalid date error = %v", err)
	}
	prepare = localCommandConfig(fixture)
	prepare.PrepareFor = "nuclei"
	if err := runPrepare(t.Context(), prepare); err == nil || !strings.Contains(err.Error(), "unsupported external tool") {
		t.Fatalf("invalid tool error = %v", err)
	}

	auditConfig := localCommandConfig(fixture)
	if err := runAudit(t.Context(), auditConfig, "xml", "none"); err == nil || !strings.Contains(err.Error(), "unsupported audit output") {
		t.Fatalf("invalid audit format error = %v", err)
	}
	if err := runAudit(t.Context(), auditConfig, "json", "critical"); err == nil || !strings.Contains(err.Error(), "fail-on") {
		t.Fatalf("invalid audit threshold error = %v", err)
	}

	bruteConfig := config.New()
	bruteConfig.NoDatabase = true
	bruteConfig.BruteAllFormats = true
	if err := runBrute(t.Context(), bruteConfig); err == nil || !strings.Contains(err.Error(), "requires --outfile") {
		t.Fatalf("all-format validation error = %v", err)
	}
	bruteConfig.BruteAllFormats = false
	bruteConfig.BruteOutputFormat = "yaml"
	if err := runBrute(t.Context(), bruteConfig); err == nil || !strings.Contains(err.Error(), "unsupported output format") {
		t.Fatalf("brute format validation error = %v", err)
	}

	missing := localCommandConfig(filepath.Join(t.TempDir(), "missing.yaml"))
	if err := runConvert(t.Context(), missing); err == nil {
		t.Fatal("convert accepted a missing local specification")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	remote := config.New()
	remote.NoDatabase = true
	remote.SwaggerURL = "https://api.example.test/openapi.yaml"
	if err := runEndpoints(canceled, remote); err == nil || !errors.Is(canceled.Err(), context.Canceled) {
		t.Fatalf("canceled endpoints error = %v, context error = %v", err, canceled.Err())
	}
}

func TestBruteTargetsValidatesAndBoundsBatchFiles(t *testing.T) {
	configValue := config.New()
	configValue.SwaggerURL = "https://api.example.test"
	targets, err := bruteTargets(configValue)
	if err != nil || len(targets) != 1 || targets[0] != configValue.SwaggerURL {
		t.Fatalf("single target = %#v, %v", targets, err)
	}

	configValue.BruteURLFile = "targets.txt"
	if _, err := bruteTargets(configValue); err == nil || !strings.Contains(err.Error(), "only one") {
		t.Fatalf("ambiguous source error = %v", err)
	}
	configValue = config.New()
	if _, err := bruteTargets(configValue); err == nil || !strings.Contains(err.Error(), "no target") {
		t.Fatalf("missing target error = %v", err)
	}

	directory := t.TempDir()
	batchPath := filepath.Join(directory, "targets.txt")
	if err := os.WriteFile(batchPath, []byte("# authorized targets\n\n https://one.example \nhttps://two.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configValue.BruteURLFile = batchPath
	configValue.MaxCandidates = 2
	targets, err = bruteTargets(configValue)
	if err != nil || len(targets) != 2 || targets[0] != "https://one.example" {
		t.Fatalf("batch targets = %#v, %v", targets, err)
	}
	configValue.MaxCandidates = 1
	if _, err := bruteTargets(configValue); err == nil || !strings.Contains(err.Error(), "target limit") {
		t.Fatalf("batch limit error = %v", err)
	}

	emptyPath := filepath.Join(directory, "empty.txt")
	if err := os.WriteFile(emptyPath, []byte("# no targets\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configValue.BruteURLFile = emptyPath
	configValue.MaxCandidates = 10
	if _, err := bruteTargets(configValue); err == nil || !strings.Contains(err.Error(), "no URLs") {
		t.Fatalf("empty batch error = %v", err)
	}
	configValue.BruteURLFile = filepath.Join(directory, "missing.txt")
	if _, err := bruteTargets(configValue); err == nil || !strings.Contains(err.Error(), "open URL file") {
		t.Fatalf("missing batch error = %v", err)
	}
}

func TestStoredReportDatasetAndRunsCommandRouteOutput(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "results.db")
	resultStore, err := store.Open(t.Context(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	run, err := resultStore.BeginRun(t.Context(), "automate", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddObservations(t.Context(), run.ID, []store.Observation{{Kind: "automate", Method: "GET", URL: "https://api.example.test/users/1", Path: "/users/1", Status: 200}}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddFindings(t.Context(), run.ID, []store.Finding{{Severity: "medium", Category: "candidate", Title: "Candidate", Method: "GET", URL: "https://api.example.test/users/1"}}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.FinishRun(t.Context(), run.ID, store.RunSucceeded, ""); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.Close(); err != nil {
		t.Fatal(err)
	}

	cfg := config.New()
	cfg.DatabasePath = databasePath
	dataset, err := storedReportDataset(t.Context(), cfg, reportCLIOptions{RunIDs: []string{run.ID}, MaxRecords: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(dataset.Operations) != 1 || len(dataset.ImportedFindings) != 1 {
		t.Fatalf("stored dataset = %#v", dataset)
	}
	noDatabase := config.New()
	noDatabase.NoDatabase = true
	if _, err := storedReportDataset(t.Context(), noDatabase, reportCLIOptions{RunIDs: []string{run.ID}}); err == nil {
		t.Fatal("stored report accepted disabled database")
	}

	previousJSON, previousLimit := runsJSON, runsLimit
	t.Cleanup(func() { runsJSON, runsLimit = previousJSON, previousLimit })
	command := &cobra.Command{}
	command.SetContext(t.Context())
	var outputBuffer bytes.Buffer
	command.SetOut(&outputBuffer)
	runsJSON, runsLimit = true, 10
	if err := runListRuns(command, cfg); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(outputBuffer.Bytes(), []byte(run.ID)) || !bytes.Contains(outputBuffer.Bytes(), []byte(`"succeeded"`)) {
		t.Fatalf("JSON runs output = %q", outputBuffer.String())
	}
	outputBuffer.Reset()
	runsJSON = false
	if err := runListRuns(command, cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(outputBuffer.String(), "RUN ID") || !strings.Contains(outputBuffer.String(), run.ID) {
		t.Fatalf("tabular runs output = %q", outputBuffer.String())
	}
	if err := runListRuns(command, noDatabase); err == nil {
		t.Fatal("runs command accepted disabled database")
	}
}

func localCommandConfig(path string) *config.Config {
	result := config.New()
	result.NoDatabase = true
	result.LocalFile = path
	result.Format = "yaml"
	result.ColorMode = config.ColorNever
	return result
}
