package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/config"
)

func TestExecuteFullWorkflowConfiguresSafeOrderedStages(t *testing.T) {
	targets := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(targets, []byte("https://api.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputDirectory := filepath.Join(t.TempDir(), "workflow")
	var calls []string
	stages := fullWorkflowStages{
		brute: func(_ context.Context, stageCfg *config.Config) error {
			calls = append(calls, "brute")
			if stageCfg.BruteWorkers != 20 || !stageCfg.BruteAllFormats || stageCfg.BruteURLFile != targets {
				t.Fatalf("brute config = %#v", stageCfg)
			}
			return nil
		},
		automate: func(_ context.Context, stageCfg *config.Config) error {
			calls = append(calls, "automate")
			if !stageCfg.StoreResponses || stageCfg.MaxStoredResponseBytes != stageCfg.MaxResponseBytes || !slices.Contains(stageCfg.ExcludeMethods, "DELETE") {
				t.Fatalf("automate config = %#v", stageCfg)
			}
			return nil
		},
		fuzz: func(_ context.Context, stageCfg *config.Config, options fuzzCLIOptions) error {
			calls = append(calls, "fuzz")
			if !stageCfg.StoreResponses || options.Scope != "idor" || options.IDORRange != "1-100" || options.MaxCases < 100 || !options.ResponseGuided || options.MaxGuidedRetries != 2 || !options.Progress {
				t.Fatalf("fuzz config=%#v options=%#v", stageCfg, options)
			}
			return nil
		},
		collection: func(_ context.Context, _ *config.Config, _ collectionCLIOptions) error {
			calls = append(calls, "collection")
			return nil
		},
		report: func(_ context.Context, _ *config.Config, options reportCLIOptions) error {
			calls = append(calls, "report")
			if options.MaxEvidence != 100 {
				t.Fatalf("report options = %#v", options)
			}
			return nil
		},
	}
	options := fullWorkflowCLIOptions{
		FullWorkflow: true, TargetsFile: targets, OutputDirectory: outputDirectory, Workers: 20,
		IDORRange: "1-100", MaxFuzzRequests: 500, MaxCases: 128, Delay: 500 * time.Millisecond,
	}
	if err := executeFullWorkflow(t.Context(), config.New(), options, stages); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"brute", "automate", "fuzz", "collection", "report"}) {
		t.Fatalf("stage order = %v", calls)
	}
}

func TestExecuteFullWorkflowStopsActiveRequestsButReportsPartialFuzzEvidence(t *testing.T) {
	targets := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(targets, []byte("https://api.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls []string
	rateErr := errors.New("rate limited")
	stages := fullWorkflowStages{
		brute:    func(context.Context, *config.Config) error { calls = append(calls, "brute"); return nil },
		automate: func(context.Context, *config.Config) error { calls = append(calls, "automate"); return nil },
		fuzz: func(context.Context, *config.Config, fuzzCLIOptions) error {
			calls = append(calls, "fuzz")
			return rateErr
		},
		collection: func(context.Context, *config.Config, collectionCLIOptions) error {
			calls = append(calls, "collection")
			return nil
		},
		report: func(context.Context, *config.Config, reportCLIOptions) error {
			calls = append(calls, "report")
			return nil
		},
	}
	options := fullWorkflowCLIOptions{
		FullWorkflow: true, TargetsFile: targets, OutputDirectory: filepath.Join(t.TempDir(), "workflow"),
		Workers: 1, IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
	}
	err := executeFullWorkflow(t.Context(), config.New(), options, stages)
	if !errors.Is(err, rateErr) {
		t.Fatalf("error = %v", err)
	}
	if !reflect.DeepEqual(calls, []string{"brute", "automate", "fuzz", "collection", "report"}) {
		t.Fatalf("partial stage order = %v", calls)
	}
}

func TestExecuteFullWorkflowRefusesExistingOutputDirectory(t *testing.T) {
	targets := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(targets, []byte("https://api.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputDirectory := t.TempDir()
	err := executeFullWorkflow(t.Context(), config.New(), fullWorkflowCLIOptions{
		FullWorkflow: true, TargetsFile: targets, OutputDirectory: outputDirectory,
		Workers: 1, IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
	}, fullWorkflowStages{})
	if err == nil {
		t.Fatal("existing output directory was accepted")
	}
}
