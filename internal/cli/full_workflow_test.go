package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	assessmentmanifest "github.com/mr-pmillz/sj/pkg/assessment/manifest"
	assessmentruntime "github.com/mr-pmillz/sj/pkg/assessment/runtime"
	"github.com/mr-pmillz/sj/pkg/brute"
	"github.com/mr-pmillz/sj/pkg/config"
)

func TestExecuteFullWorkflowConfiguresSafeOrderedStages(t *testing.T) {
	targets := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(targets, []byte("https://api.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	specialCharacters := filepath.Join(t.TempDir(), "special-characters.txt")
	if err := os.WriteFile(specialCharacters, []byte("!\n%21\n"), 0o600); err != nil {
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
			if !stageCfg.StoreResponses || stageCfg.MaxStoredResponseBytes != stageCfg.MaxResponseBytes ||
				!slices.Contains(stageCfg.ExcludeMethods, "DELETE") || !slices.Contains(stageCfg.ExcludeMethods, "PATCH") ||
				!slices.Contains(stageCfg.ExcludeMethods, "POST") {
				t.Fatalf("automate config = %#v", stageCfg)
			}
			return nil
		},
		fuzz: func(_ context.Context, stageCfg *config.Config, options fuzzCLIOptions) error {
			calls = append(calls, "fuzz")
			if !stageCfg.StoreResponses || options.Scope != "idor" || options.IDORRange != "1-100" || options.MaxCases < 100 || !reflect.DeepEqual(options.SpecialCharacters, []string{"!", "%21"}) || options.SpecialCharsWordlist != "" || !options.ResponseGuided || options.MaxGuidedRetries != 2 || !options.Progress || !options.ContinueOnTargetError {
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
		SpecialCharsWordlist: specialCharacters,
	}
	if err := executeFullWorkflow(t.Context(), config.New(), options, stages); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"brute", "automate", "fuzz", "collection", "report"}) {
		t.Fatalf("stage order = %v", calls)
	}
}

func TestExecuteFullWorkflowRejectsInvalidSpecialCharacterWordlistBeforeSideEffects(t *testing.T) {
	directory := t.TempDir()
	targets := filepath.Join(directory, "targets.txt")
	if err := os.WriteFile(targets, []byte("https://api.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wordlist := filepath.Join(directory, "special-characters.txt")
	if err := os.WriteFile(wordlist, []byte("not-one-character\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputDirectory := filepath.Join(directory, "workflow")
	called := false
	stages := fullWorkflowStages{
		brute: func(context.Context, *config.Config) error { called = true; return nil },
	}
	err := executeFullWorkflow(t.Context(), config.New(), fullWorkflowCLIOptions{
		FullWorkflow: true, TargetsFile: targets, OutputDirectory: outputDirectory, Workers: 1,
		IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
		SpecialCharsWordlist: wordlist,
	}, stages)
	if err == nil || !strings.Contains(err.Error(), "special-character wordlist") {
		t.Fatalf("invalid wordlist error = %v", err)
	}
	if called {
		t.Fatal("a workflow stage ran before special-character wordlist validation")
	}
	if _, statErr := os.Stat(outputDirectory); !os.IsNotExist(statErr) {
		t.Fatalf("output directory was created before wordlist validation: %v", statErr)
	}
}

func TestExecuteFullWorkflowSkipsBruteForDirectSpecificationURLs(t *testing.T) {
	specs := filepath.Join(t.TempDir(), "specs.txt")
	if err := os.WriteFile(specs, []byte("https://api.example/openapi.json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls []string
	stages := fullWorkflowStages{
		brute: func(context.Context, *config.Config) error {
			t.Fatal("brute stage was called")
			return nil
		},
		automate: func(_ context.Context, stageCfg *config.Config) error {
			calls = append(calls, "automate")
			if stageCfg.AutomateURLFile != specs || len(stageCfg.AutomateRunIDs) != 0 {
				t.Fatalf("automate source = file:%q runs:%v", stageCfg.AutomateURLFile, stageCfg.AutomateRunIDs)
			}
			return nil
		},
		fuzz: func(context.Context, *config.Config, fuzzCLIOptions) error { calls = append(calls, "fuzz"); return nil },
		collection: func(context.Context, *config.Config, collectionCLIOptions) error {
			calls = append(calls, "collection")
			return nil
		},
		report: func(_ context.Context, _ *config.Config, options reportCLIOptions) error {
			calls = append(calls, "report")
			if slices.Contains(options.Inputs, filepath.Join(filepath.Dir(options.Inputs[0]), "brute.json")) {
				t.Fatalf("skipped brute artifact included in report: %v", options.Inputs)
			}
			return nil
		},
	}
	err := executeFullWorkflow(t.Context(), config.New(), fullWorkflowCLIOptions{
		FullWorkflow: true, SkipBrute: true, TargetsFile: specs, OutputDirectory: filepath.Join(t.TempDir(), "workflow"),
		Workers: 1, IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
	}, stages)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"automate", "fuzz", "collection", "report"}) {
		t.Fatalf("calls = %v", calls)
	}
}

func TestExecuteFullWorkflowResumesStoredBruteRuns(t *testing.T) {
	commandConfig := config.New()
	commandConfig.DatabasePath = filepath.Join(t.TempDir(), "retained.db")
	stages := fullWorkflowStages{
		brute: func(context.Context, *config.Config) error {
			t.Fatal("brute stage was called")
			return nil
		},
		automate: func(_ context.Context, stageCfg *config.Config) error {
			if stageCfg.AutomateURLFile != "" || !reflect.DeepEqual(stageCfg.AutomateRunIDs, []string{"brute-a", "brute-b"}) {
				t.Fatalf("automate source = file:%q runs:%v", stageCfg.AutomateURLFile, stageCfg.AutomateRunIDs)
			}
			return nil
		},
		fuzz:       func(context.Context, *config.Config, fuzzCLIOptions) error { return nil },
		collection: func(context.Context, *config.Config, collectionCLIOptions) error { return nil },
		report:     func(context.Context, *config.Config, reportCLIOptions) error { return nil },
	}
	err := executeFullWorkflow(t.Context(), commandConfig, fullWorkflowCLIOptions{
		FullWorkflow: true, SkipBrute: true, BruteRunIDs: []string{"brute-a", "brute-b"},
		OutputDirectory: filepath.Join(t.TempDir(), "workflow"), Workers: 1,
		IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
	}, stages)
	if err != nil {
		t.Fatal(err)
	}
}

func TestExecuteFullWorkflowSanitizesGlobalTransportForAssessment(t *testing.T) {
	t.Setenv(assessmentEvidenceKeyEnvironment, strings.Repeat("5a", 32))
	directory := t.TempDir()
	specs := filepath.Join(directory, "specs.txt")
	manifest := filepath.Join(directory, "assessment.yaml")
	if err := os.WriteFile(specs, []byte("https://api.example/openapi.json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte(fullWorkflowAssessmentTemplate()), 0o600); err != nil {
		t.Fatal(err)
	}
	commandConfig := config.New()
	commandConfig.SOCKS5Proxy = "socks5://127.0.0.1:9000"
	stages := fullWorkflowStages{
		automate:   func(context.Context, *config.Config) error { return nil },
		fuzz:       func(context.Context, *config.Config, fuzzCLIOptions) error { return nil },
		collection: func(context.Context, *config.Config, collectionCLIOptions) error { return nil },
		report:     func(context.Context, *config.Config, reportCLIOptions) error { return nil },
		assessment: func(_ context.Context, stageCfg *config.Config, _ fullWorkflowAssessmentRequest) error {
			if stageCfg.SOCKS5Proxy != "" || stageCfg.Proxy != "NOPROXY" || stageCfg.ReplayProxy != "" || stageCfg.Insecure {
				t.Fatalf("assessment inherited global transport overrides: %#v", stageCfg)
			}
			return nil
		},
	}
	err := executeFullWorkflow(t.Context(), commandConfig, fullWorkflowCLIOptions{
		FullWorkflow: true, SkipBrute: true, TargetsFile: specs, AssessmentManifest: manifest,
		OutputDirectory: filepath.Join(directory, "workflow"), Workers: 1,
		IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
	}, stages)
	if err != nil {
		t.Fatal(err)
	}
}

func TestExecuteFullWorkflowAutoAssessmentMaterializesStrictAnonymousManifest(t *testing.T) {
	t.Setenv(assessmentEvidenceKeyEnvironment, strings.Repeat("5a", 32))
	directory := t.TempDir()
	specs := filepath.Join(directory, "specs.txt")
	if err := os.WriteFile(specs, []byte("https://api.example/openapi.json\nhttps://second.example/spec.json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	commandConfig := config.New()
	commandConfig.SOCKS5Proxy = "socks5://127.0.0.1:9000"
	assessmentCalled := false
	stages := fullWorkflowStages{
		automate: func(_ context.Context, stageCfg *config.Config) error {
			return os.WriteFile(stageCfg.Outfile+".json", []byte(`{"results":[]}`), 0o600)
		},
		fuzz:       func(context.Context, *config.Config, fuzzCLIOptions) error { return nil },
		collection: func(context.Context, *config.Config, collectionCLIOptions) error { return nil },
		report:     func(context.Context, *config.Config, reportCLIOptions) error { return nil },
		assessment: func(_ context.Context, _ *config.Config, request fullWorkflowAssessmentRequest) error {
			assessmentCalled = true
			if !request.ManifestPrepared {
				t.Fatal("automatic manifest was not prepared before network stages")
			}
			contents, err := os.ReadFile(request.ManifestPath)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := assessmentmanifest.Parse(contents, assessmentmanifest.LoadOptions{})
			if err != nil {
				t.Fatalf("automatic manifest is invalid: %v", err)
			}
			if len(loaded.Origins()) != 2 || len(loaded.Identities()) != 0 || len(loaded.OwnedObjects()) != 0 {
				t.Fatalf("automatic manifest inferred authorization facts: origins=%d identities=%d objects=%d", len(loaded.Origins()), len(loaded.Identities()), len(loaded.OwnedObjects()))
			}
			if loaded.Transport().Proxy().URL() != "socks5://127.0.0.1:9000" || !loaded.Transport().Proxy().Required() {
				t.Fatalf("automatic manifest transport = %#v", loaded.Transport())
			}
			return nil
		},
	}
	err := executeFullWorkflow(t.Context(), commandConfig, fullWorkflowCLIOptions{
		FullWorkflow: true, SkipBrute: true, AutoAssess: true, TargetsFile: specs,
		OutputDirectory: filepath.Join(directory, "workflow"), Workers: 1,
		IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
	}, stages)
	if err != nil {
		t.Fatal(err)
	}
	if !assessmentCalled {
		t.Fatal("automatic assessment stage was not called")
	}
}

func TestExecuteFullWorkflowRequiresIndependentPostAndPatchOptIns(t *testing.T) {
	targets := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(targets, []byte("https://api.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		allowPost  bool
		allowPatch bool
		wantPost   bool
		wantPatch  bool
	}{
		{name: "neither"},
		{name: "post only", allowPost: true, wantPost: true},
		{name: "patch only", allowPatch: true, wantPatch: true},
		{name: "both", allowPost: true, allowPatch: true, wantPost: true, wantPatch: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stages := fullWorkflowStages{
				brute: func(context.Context, *config.Config) error { return nil },
				automate: func(_ context.Context, stageCfg *config.Config) error {
					if got := !slices.Contains(stageCfg.ExcludeMethods, "POST"); got != test.wantPost {
						t.Fatalf("POST enabled = %v, want %v; exclusions=%v", got, test.wantPost, stageCfg.ExcludeMethods)
					}
					if got := stageCfg.AllowPatch && !slices.Contains(stageCfg.ExcludeMethods, "PATCH"); got != test.wantPatch {
						t.Fatalf("PATCH enabled = %v, want %v; allow=%v exclusions=%v", got, test.wantPatch, stageCfg.AllowPatch, stageCfg.ExcludeMethods)
					}
					if slices.Contains(stageCfg.ExcludeMethods, "DELETE") == false {
						t.Fatal("DELETE was not excluded")
					}
					return nil
				},
				fuzz:       func(context.Context, *config.Config, fuzzCLIOptions) error { return nil },
				collection: func(context.Context, *config.Config, collectionCLIOptions) error { return nil },
				report:     func(context.Context, *config.Config, reportCLIOptions) error { return nil },
			}
			err := executeFullWorkflow(t.Context(), config.New(), fullWorkflowCLIOptions{
				FullWorkflow: true, TargetsFile: targets, OutputDirectory: filepath.Join(t.TempDir(), "workflow"),
				Workers: 1, IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
				AcceptRisk: true, AllowPost: test.allowPost, AllowPatch: test.allowPatch,
			}, stages)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestExecuteFullWorkflowContinuesFromPartialAutomateCorpus(t *testing.T) {
	targets := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(targets, []byte("https://one.example\nhttps://two.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls []string
	partialCause := errors.New("one specification source failed")
	partial := &automatePartialFailure{failed: 1, total: 2, err: partialCause}
	stages := fullWorkflowStages{
		brute: func(context.Context, *config.Config) error {
			calls = append(calls, "brute")
			return nil
		},
		automate: func(_ context.Context, stageCfg *config.Config) error {
			calls = append(calls, "automate")
			if err := os.WriteFile(stageCfg.Outfile+".json", []byte(`{"results":[]}`), 0o600); err != nil {
				t.Fatal(err)
			}
			return partial
		},
		fuzz: func(_ context.Context, _ *config.Config, options fuzzCLIOptions) error {
			calls = append(calls, "fuzz")
			if !options.ContinueOnTargetError {
				t.Fatal("full workflow fuzz did not isolate target-local failures")
			}
			return nil
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
	err := executeFullWorkflow(t.Context(), config.New(), fullWorkflowCLIOptions{
		FullWorkflow: true, TargetsFile: targets, OutputDirectory: filepath.Join(t.TempDir(), "workflow"),
		Workers: 2, IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
	}, stages)
	if err != nil {
		t.Fatalf("partial target failure aborted full workflow: %v", err)
	}
	if !reflect.DeepEqual(calls, []string{"brute", "automate", "fuzz", "collection", "report"}) {
		t.Fatalf("stage order = %v", calls)
	}
}

func TestExecuteFullWorkflowContinuesFromContainedBruteTargetFailure(t *testing.T) {
	targets := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(targets, []byte("https://bad.example\nhttps://healthy.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls []string
	stages := fullWorkflowStages{
		brute: func(_ context.Context, stageCfg *config.Config) error {
			calls = append(calls, "brute")
			if err := os.WriteFile(stageCfg.Outfile+".json", []byte(`[]`), 0o600); err != nil {
				t.Fatal(err)
			}
			return brute.NewPartialBatchError(errors.New("bad target failed"))
		},
		automate: func(context.Context, *config.Config) error { calls = append(calls, "automate"); return nil },
		fuzz: func(context.Context, *config.Config, fuzzCLIOptions) error {
			calls = append(calls, "fuzz")
			return nil
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
	err := executeFullWorkflow(t.Context(), config.New(), fullWorkflowCLIOptions{
		FullWorkflow: true, TargetsFile: targets, OutputDirectory: filepath.Join(t.TempDir(), "workflow"),
		Workers: 2, IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
	}, stages)
	if err != nil {
		t.Fatalf("contained brute target failure aborted workflow: %v", err)
	}
	if !reflect.DeepEqual(calls, []string{"brute", "automate", "fuzz", "collection", "report"}) {
		t.Fatalf("stage order = %v", calls)
	}
}

func TestExecuteFullWorkflowStopsActiveStagesAfterGlobalBruteFailure(t *testing.T) {
	targets := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(targets, []byte("https://api.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := errors.New("brute evidence persistence failed")
	var calls []string
	stages := fullWorkflowStages{
		brute: func(_ context.Context, stageCfg *config.Config) error {
			calls = append(calls, "brute")
			if err := os.WriteFile(stageCfg.Outfile+".json", []byte(`[]`), 0o600); err != nil {
				t.Fatal(err)
			}
			return want
		},
		automate: func(context.Context, *config.Config) error { calls = append(calls, "automate"); return nil },
	}
	err := executeFullWorkflow(t.Context(), config.New(), fullWorkflowCLIOptions{
		FullWorkflow: true, TargetsFile: targets, OutputDirectory: filepath.Join(t.TempDir(), "workflow"),
		Workers: 1, IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
	}, stages)
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want global brute failure", err)
	}
	if !reflect.DeepEqual(calls, []string{"brute"}) {
		t.Fatalf("active stages continued after global brute failure: %v", calls)
	}
}

func TestExecuteFullWorkflowStopsActiveStagesAfterGlobalAutomateFailure(t *testing.T) {
	t.Setenv(assessmentEvidenceKeyEnvironment, strings.Repeat("5a", 32))
	directory := t.TempDir()
	targets := filepath.Join(directory, "targets.txt")
	manifest := filepath.Join(directory, "assessment.yaml")
	if err := os.WriteFile(targets, []byte("https://api.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte(fullWorkflowAssessmentTemplate()), 0o600); err != nil {
		t.Fatal(err)
	}
	want := errors.New("automate database failed")
	var calls []string
	stages := fullWorkflowStages{
		brute: func(context.Context, *config.Config) error { calls = append(calls, "brute"); return nil },
		automate: func(_ context.Context, stageCfg *config.Config) error {
			calls = append(calls, "automate")
			if err := os.WriteFile(stageCfg.Outfile+".json", []byte(`{"results":[]}`), 0o600); err != nil {
				t.Fatal(err)
			}
			return want
		},
		fuzz: func(context.Context, *config.Config, fuzzCLIOptions) error {
			calls = append(calls, "fuzz")
			return nil
		},
		collection: func(context.Context, *config.Config, collectionCLIOptions) error {
			calls = append(calls, "collection")
			return nil
		},
		report: func(context.Context, *config.Config, reportCLIOptions) error {
			calls = append(calls, "report")
			return nil
		},
		assessment: func(context.Context, *config.Config, fullWorkflowAssessmentRequest) error {
			calls = append(calls, "assessment")
			return nil
		},
	}
	err := executeFullWorkflow(t.Context(), config.New(), fullWorkflowCLIOptions{
		FullWorkflow: true, TargetsFile: targets, OutputDirectory: filepath.Join(directory, "workflow"),
		Workers: 1, IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
		AssessmentManifest: manifest,
	}, stages)
	if !errors.Is(err, want) || !strings.Contains(err.Error(), "assessment stage: skipped") {
		t.Fatalf("error = %v, want global automate failure and assessment skip", err)
	}
	if !reflect.DeepEqual(calls, []string{"brute", "automate", "collection", "report"}) {
		t.Fatalf("active stages continued after global automate failure: %v", calls)
	}
}

func TestSuppressAutomatePartialFailurePreservesGlobalStageErrors(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "automate.json")
	if err := os.WriteFile(artifact, []byte(`{"results":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	partial := &automatePartialFailure{failed: 1, total: 2, err: errors.New("bad source")}
	if err := suppressAutomatePartialFailure(partial, artifact); err != nil {
		t.Fatalf("contained source failure was not suppressed: %v", err)
	}
	allFailed := &automatePartialFailure{failed: 2, total: 2, err: errors.New("shared transport failed")}
	if err := suppressAutomatePartialFailure(allFailed, artifact); !errors.Is(err, allFailed) {
		t.Fatalf("all-source failure was suppressed: %v", err)
	}
	global := errors.New("persist automate output")
	if err := suppressAutomatePartialFailure(global, artifact); !errors.Is(err, global) {
		t.Fatalf("global failure was suppressed: %v", err)
	}
}

func TestExecuteFullWorkflowChainsManifestAssessmentAfterLegacyReport(t *testing.T) {
	t.Setenv(assessmentEvidenceKeyEnvironment, strings.Repeat("5a", 32))
	directory := t.TempDir()
	targets := filepath.Join(directory, "targets.txt")
	manifest := filepath.Join(directory, "assessment.yaml")
	if err := os.WriteFile(targets, []byte("https://api.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte(fullWorkflowAssessmentTemplate()), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls []string
	stages := fullWorkflowStages{
		brute: func(context.Context, *config.Config) error {
			calls = append(calls, "brute")
			return nil
		},
		automate: func(context.Context, *config.Config) error {
			calls = append(calls, "automate")
			return nil
		},
		fuzz: func(context.Context, *config.Config, fuzzCLIOptions) error {
			calls = append(calls, "fuzz")
			return nil
		},
		collection: func(context.Context, *config.Config, collectionCLIOptions) error {
			calls = append(calls, "collection")
			return nil
		},
		report: func(context.Context, *config.Config, reportCLIOptions) error {
			calls = append(calls, "report")
			return nil
		},
		assessment: func(_ context.Context, _ *config.Config, request fullWorkflowAssessmentRequest) error {
			calls = append(calls, "assessment")
			if request.SourceManifestPath != manifest || !request.ManifestPrepared || request.MaxResults != 321 {
				t.Fatalf("assessment request = %#v", request)
			}
			if filepath.Base(request.ManifestPath) != "assessment-manifest.yaml" || filepath.Base(request.AutomateResultsPath) != "automate.json" || filepath.Base(request.DatabasePath) != "assessment.db" || filepath.Base(request.PlanPath) != "assessment-plan.json" || filepath.Base(request.RunPath) != "assessment-run.json" {
				t.Fatalf("assessment artifact paths = %#v", request)
			}
			wantReports := []fullWorkflowAssessmentReport{
				{Format: "json", Path: filepath.Join(request.OutputDirectory, "assessment-report.json")},
				{Format: "markdown", Path: filepath.Join(request.OutputDirectory, "assessment-report.md")},
				{Format: "html", Path: filepath.Join(request.OutputDirectory, "assessment-report.html")},
				{Format: "sarif", Path: filepath.Join(request.OutputDirectory, "assessment-report.sarif.json")},
				{Format: "junit", Path: filepath.Join(request.OutputDirectory, "assessment-report.junit.xml")},
				{Format: "bruno", Path: filepath.Join(request.OutputDirectory, "assessment-reproduction.zip")},
			}
			if !reflect.DeepEqual(request.Reports, wantReports) {
				t.Fatalf("assessment reports = %#v", request.Reports)
			}
			return nil
		},
	}
	options := fullWorkflowCLIOptions{
		FullWorkflow: true, TargetsFile: targets, OutputDirectory: filepath.Join(directory, "workflow"),
		Workers: 1, IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
		AssessmentManifest: manifest, AssessmentMaxResults: 321,
	}
	if err := executeFullWorkflow(t.Context(), config.New(), options, stages); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"brute", "automate", "fuzz", "collection", "report", "assessment"}) {
		t.Fatalf("stage order = %v", calls)
	}
}

func TestExecuteFullWorkflowRejectsManifestOriginOutsideTargetFileBeforeNetwork(t *testing.T) {
	t.Setenv(assessmentEvidenceKeyEnvironment, strings.Repeat("5a", 32))
	directory := t.TempDir()
	targets := filepath.Join(directory, "targets.txt")
	manifest := filepath.Join(directory, "assessment.yaml")
	if err := os.WriteFile(targets, []byte("https://authorized.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	template := strings.ReplaceAll(fullWorkflowAssessmentTemplate(), "https://api.example", "https://outside.example")
	if err := os.WriteFile(manifest, []byte(template), 0o600); err != nil {
		t.Fatal(err)
	}
	networkStages := 0
	stages := fullWorkflowStages{
		brute:    func(context.Context, *config.Config) error { networkStages++; return nil },
		automate: func(context.Context, *config.Config) error { networkStages++; return nil },
	}
	err := executeFullWorkflow(t.Context(), config.New(), fullWorkflowCLIOptions{
		FullWorkflow: true, TargetsFile: targets, OutputDirectory: filepath.Join(directory, "workflow"),
		Workers: 1, IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
		AssessmentManifest: manifest,
	}, stages)
	if err == nil || !strings.Contains(err.Error(), "not authorized by --url-file") {
		t.Fatalf("error = %v, want manifest-origin authorization failure", err)
	}
	if networkStages != 0 {
		t.Fatalf("network stages called before assessment scope preflight: %d", networkStages)
	}
}

func TestExecuteFullWorkflowAssessmentRequiresPersistedEvidence(t *testing.T) {
	directory := t.TempDir()
	targets := filepath.Join(directory, "targets.txt")
	manifest := filepath.Join(directory, "assessment.yaml")
	for path, contents := range map[string]string{targets: "https://api.example\n", manifest: fullWorkflowAssessmentTemplate()} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	commandConfig := config.New()
	commandConfig.NoDatabase = true
	err := executeFullWorkflow(t.Context(), commandConfig, fullWorkflowCLIOptions{
		FullWorkflow: true, TargetsFile: targets, OutputDirectory: filepath.Join(directory, "workflow"),
		Workers: 1, IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
		AssessmentManifest: manifest,
	}, fullWorkflowStages{})
	if err == nil || !strings.Contains(err.Error(), "--no-database") {
		t.Fatalf("error = %v, want persisted assessment evidence rejection", err)
	}
}

func TestExecuteFullWorkflowAssessmentPreflightFailsBeforeStages(t *testing.T) {
	directory := t.TempDir()
	targets := filepath.Join(directory, "targets.txt")
	manifest := filepath.Join(directory, "assessment.yaml")
	for path, contents := range map[string]string{targets: "https://api.example\n", manifest: fullWorkflowAssessmentTemplate()} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(assessmentEvidenceKeyEnvironment, "")
	outputDirectory := filepath.Join(directory, "missing-key")
	err := executeFullWorkflow(t.Context(), config.New(), fullWorkflowCLIOptions{
		FullWorkflow: true, TargetsFile: targets, OutputDirectory: outputDirectory,
		Workers: 1, IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
		AssessmentManifest: manifest,
	}, fullWorkflowStages{})
	if err == nil || !strings.Contains(err.Error(), assessmentEvidenceKeyEnvironment) {
		t.Fatalf("missing evidence-key preflight error = %v", err)
	}
	if _, statErr := os.Stat(outputDirectory); !os.IsNotExist(statErr) {
		t.Fatalf("output directory was created before preflight failure: %v", statErr)
	}
}

func TestExecuteFullWorkflowSkipsAssessmentAfterFuzzFailure(t *testing.T) {
	t.Setenv(assessmentEvidenceKeyEnvironment, strings.Repeat("5a", 32))
	directory := t.TempDir()
	targets := filepath.Join(directory, "targets.txt")
	manifest := filepath.Join(directory, "assessment.yaml")
	for path, contents := range map[string]string{targets: "https://api.example\n", manifest: fullWorkflowAssessmentTemplate()} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want := errors.New("bounded fuzz stopped")
	var calls []string
	stages := fullWorkflowStages{
		brute:    func(context.Context, *config.Config) error { calls = append(calls, "brute"); return nil },
		automate: func(context.Context, *config.Config) error { calls = append(calls, "automate"); return nil },
		fuzz: func(context.Context, *config.Config, fuzzCLIOptions) error {
			calls = append(calls, "fuzz")
			return want
		},
		collection: func(context.Context, *config.Config, collectionCLIOptions) error {
			calls = append(calls, "collection")
			return nil
		},
		report: func(context.Context, *config.Config, reportCLIOptions) error {
			calls = append(calls, "report")
			return nil
		},
		assessment: func(context.Context, *config.Config, fullWorkflowAssessmentRequest) error {
			calls = append(calls, "assessment")
			return nil
		},
	}
	err := executeFullWorkflow(t.Context(), config.New(), fullWorkflowCLIOptions{
		FullWorkflow: true, TargetsFile: targets, OutputDirectory: filepath.Join(directory, "workflow"),
		Workers: 1, IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
		AssessmentManifest: manifest,
	}, stages)
	if !errors.Is(err, want) || !strings.Contains(err.Error(), "assessment stage: skipped") {
		t.Fatalf("error = %v", err)
	}
	if !reflect.DeepEqual(calls, []string{"brute", "automate", "fuzz", "collection", "report"}) {
		t.Fatalf("stage order = %v", calls)
	}
}

func TestExecuteFullWorkflowMaterializesAssessmentManifestBeforeStages(t *testing.T) {
	t.Setenv(assessmentEvidenceKeyEnvironment, strings.Repeat("5a", 32))
	directory := t.TempDir()
	targets := filepath.Join(directory, "targets.txt")
	manifest := filepath.Join(directory, "assessment.yaml")
	if err := os.WriteFile(targets, []byte("https://api.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("spec: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls []string
	stages := fullWorkflowStages{
		brute: func(context.Context, *config.Config) error {
			calls = append(calls, "brute")
			return nil
		},
	}
	err := executeFullWorkflow(t.Context(), config.New(), fullWorkflowCLIOptions{
		FullWorkflow: true, TargetsFile: targets, OutputDirectory: filepath.Join(directory, "workflow"),
		Workers: 1, IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
		AssessmentManifest: manifest,
	}, stages)
	if err == nil || !strings.Contains(err.Error(), "materialize manifest") {
		t.Fatalf("error = %v, want early materialization failure", err)
	}
	if len(calls) != 0 {
		t.Fatalf("stages ran before manifest materialization failed: %v", calls)
	}
}

func TestExecuteFullWorkflowAssessmentRequiresExplicitAuthorizationFacts(t *testing.T) {
	t.Setenv(assessmentEvidenceKeyEnvironment, strings.Repeat("5a", 32))
	directory := t.TempDir()
	targets := filepath.Join(directory, "targets.txt")
	manifest := filepath.Join(directory, "assessment.yaml")
	if err := os.WriteFile(targets, []byte("https://api.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	contents := fullWorkflowAssessmentTemplate()
	identityStart := strings.Index(contents, "  identities:\n")
	modulesStart := strings.Index(contents, "  modules:\n")
	if identityStart < 0 || modulesStart <= identityStart {
		t.Fatal("assessment template fixture is missing identity or module sections")
	}
	contents = contents[:identityStart] + "  identities: []\n  ownedObjects: []\n" + contents[modulesStart:]
	if err := os.WriteFile(manifest, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls int
	err := executeFullWorkflow(t.Context(), config.New(), fullWorkflowCLIOptions{
		FullWorkflow: true, TargetsFile: targets, OutputDirectory: filepath.Join(directory, "workflow"),
		Workers: 1, IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
		AssessmentManifest: manifest,
	}, fullWorkflowStages{brute: func(context.Context, *config.Config) error { calls++; return nil }})
	if err == nil || !strings.Contains(err.Error(), "authorization facts") {
		t.Fatalf("error = %v, want explicit authorization-facts rejection", err)
	}
	if calls != 0 {
		t.Fatalf("network stage ran before authorization-facts validation: %d", calls)
	}
}

func TestExecuteFullWorkflowPinsAssessmentTemplateBeforeNetworkStages(t *testing.T) {
	t.Setenv(assessmentEvidenceKeyEnvironment, strings.Repeat("5a", 32))
	directory := t.TempDir()
	targets := filepath.Join(directory, "targets.txt")
	manifest := filepath.Join(directory, "assessment.yaml")
	if err := os.WriteFile(targets, []byte("https://api.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte(fullWorkflowAssessmentTemplate()), 0o600); err != nil {
		t.Fatal(err)
	}
	stages := fullWorkflowStages{
		brute: func(context.Context, *config.Config) error {
			return os.WriteFile(manifest, []byte("attacker-controlled: true\n"), 0o600)
		},
		automate: func(context.Context, *config.Config) error { return nil },
		fuzz:     func(context.Context, *config.Config, fuzzCLIOptions) error { return nil },
		collection: func(context.Context, *config.Config, collectionCLIOptions) error {
			return nil
		},
		report: func(context.Context, *config.Config, reportCLIOptions) error { return nil },
		assessment: func(_ context.Context, _ *config.Config, request fullWorkflowAssessmentRequest) error {
			contents, err := os.ReadFile(request.ManifestPath)
			if err != nil {
				return err
			}
			if strings.Contains(string(contents), "attacker-controlled") ||
				!strings.Contains(string(contents), "name: workflow-assessment") {
				return errors.New("assessment manifest was not pinned")
			}
			return nil
		},
	}
	err := executeFullWorkflow(t.Context(), config.New(), fullWorkflowCLIOptions{
		FullWorkflow: true, TargetsFile: targets, OutputDirectory: filepath.Join(directory, "workflow"),
		Workers: 1, IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
		AssessmentManifest: manifest,
	}, stages)
	if err != nil {
		t.Fatal(err)
	}
}

func TestMaterializeFullWorkflowAssessmentManifestReplacesOnlyAutomateInputPath(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source.yaml")
	destination := filepath.Join(directory, "materialized.yaml")
	automateResults := filepath.Join(directory, "automate.json")
	contents := `apiVersion: sj.dev/v1alpha1
kind: Assessment
metadata:
  name: workflow-assessment
spec:
  inputs:
    - name: workflow-results
      kind: sj-results
      path: $workflow.automate
  identities:
    - name: user-a
      headers:
        X-Canary: $workflow.automate
`
	if err := os.WriteFile(source, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := materializeFullWorkflowAssessmentManifest(source, destination, automateResults); err != nil {
		t.Fatal(err)
	}
	materialized, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(materialized), "path: "+automateResults) {
		t.Fatalf("materialized manifest did not reference automate results:\n%s", materialized)
	}
	if !strings.Contains(string(materialized), "X-Canary: $workflow.automate") {
		t.Fatalf("non-input placeholder was unexpectedly replaced:\n%s", materialized)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("manifest mode = %o, want 600", info.Mode().Perm())
	}
}

func TestMaterializeFullWorkflowAssessmentManifestRejectsUnsafeTemplates(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.yaml")
	if err := os.WriteFile(target, []byte("spec: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "symlink.yaml")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		path     string
		contents string
	}{
		{name: "symlink", path: symlink},
		{name: "multiple documents", path: filepath.Join(directory, "multiple.yaml"), contents: "spec: {}\n---\nspec: {}\n"},
		{name: "malformed YAML", path: filepath.Join(directory, "malformed.yaml"), contents: "spec: [\n"},
		{name: "missing workflow binding", path: filepath.Join(directory, "missing-binding.yaml"), contents: "spec:\n  inputs: []\n"},
		{name: "wrong input kind", path: filepath.Join(directory, "wrong-kind.yaml"), contents: "spec:\n  inputs:\n    - kind: openapi\n      path: $workflow.automate\n"},
		{name: "duplicate workflow binding", path: filepath.Join(directory, "duplicate-binding.yaml"), contents: "spec:\n  inputs:\n    - kind: sj-results\n      path: $workflow.automate\n    - kind: sj-results\n      path: $workflow.automate\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.contents != "" {
				if err := os.WriteFile(test.path, []byte(test.contents), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			err := materializeFullWorkflowAssessmentManifest(
				test.path,
				filepath.Join(directory, test.name+"-materialized.yaml"),
				filepath.Join(directory, "automate.json"),
			)
			if err == nil {
				t.Fatal("unsafe assessment template was accepted")
			}
		})
	}
}

func TestExecuteFullWorkflowAssessmentPersistsPrivateLifecycleArtifacts(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source.yaml")
	if err := os.WriteFile(source, []byte("spec:\n  inputs:\n    - kind: sj-results\n      path: $workflow.automate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	request := fullWorkflowAssessmentRequest{
		SourceManifestPath:  source,
		ManifestPath:        filepath.Join(directory, "assessment-manifest.yaml"),
		AutomateResultsPath: filepath.Join(directory, "automate.json"),
		OutputDirectory:     directory,
		DatabasePath:        filepath.Join(directory, "assessment.db"),
		PlanPath:            filepath.Join(directory, "assessment-plan.json"),
		RunPath:             filepath.Join(directory, "assessment-run.json"),
		Reports:             fullWorkflowAssessmentReports(directory),
		MaxResults:          47,
	}
	backend := &fakeAssessmentRuntime{
		plan:   assessmentruntime.PlanResult{PlanHash: "plan-hash", Nodes: 2, Requests: 10},
		run:    assessmentruntime.RunResult{AssessmentID: "assessment-123"},
		report: []byte("assessment report artifact"),
	}
	if err := executeFullWorkflowAssessment(t.Context(), backend, request); err != nil {
		t.Fatal(err)
	}
	for _, path := range append(
		[]string{request.ManifestPath, request.PlanPath, request.RunPath},
		fullWorkflowAssessmentReportPaths(request.Reports)...,
	) {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("artifact %s mode = %o, want 600", path, info.Mode().Perm())
		}
	}
	plan, err := os.ReadFile(request.PlanPath)
	if err != nil || !strings.Contains(string(plan), `"plan_hash": "plan-hash"`) {
		t.Fatalf("plan artifact = %q, error = %v", plan, err)
	}
	run, err := os.ReadFile(request.RunPath)
	if err != nil || !strings.Contains(string(run), `"assessment_id": "assessment-123"`) {
		t.Fatalf("run artifact = %q, error = %v", run, err)
	}
	if backend.reportRequest.MaxResults != 47 || backend.reportRequest.DatabasePath != request.DatabasePath {
		t.Fatalf("last report request = %#v", backend.reportRequest)
	}
}

func TestExecuteFullWorkflowAssessmentAllowsEmptyPlanOnlyForAutomaticMode(t *testing.T) {
	directory := t.TempDir()
	automate := filepath.Join(directory, "automate.json")
	manifest := filepath.Join(directory, "assessment-manifest.yaml")
	for path, contents := range map[string]string{automate: `{"results":[]}`, manifest: "manifest"} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	backend := &fakeAssessmentRuntime{
		plan: assessmentruntime.PlanResult{PlanHash: "empty-plan"},
		run:  assessmentruntime.RunResult{AssessmentID: "assessment-empty"}, report: []byte("report"),
	}
	request := fullWorkflowAssessmentRequest{
		ManifestPath: manifest, AutomateResultsPath: automate, ManifestPrepared: true,
		DatabasePath: filepath.Join(directory, "assessment.db"), PlanPath: filepath.Join(directory, "plan.json"),
		RunPath: filepath.Join(directory, "run.json"), Reports: fullWorkflowAssessmentReports(directory),
		AllowNoCandidates: true,
	}
	if err := executeFullWorkflowAssessment(t.Context(), backend, request); err != nil {
		t.Fatal(err)
	}
	if !backend.planRequest.AllowNoCandidates || !backend.runRequest.AllowNoCandidates {
		t.Fatalf("automatic empty-plan policy was not propagated: plan=%#v run=%#v", backend.planRequest, backend.runRequest)
	}
}

type partialRunAssessmentRuntime struct {
	fakeAssessmentRuntime
	runErr      error
	reportErr   error
	reportCalls int
}

func (runtime *partialRunAssessmentRuntime) Run(context.Context, assessmentruntime.RunRequest) (assessmentruntime.RunResult, error) {
	return runtime.run, runtime.runErr
}

func (runtime *partialRunAssessmentRuntime) Report(_ context.Context, request assessmentruntime.ReportRequest) ([]byte, error) {
	runtime.reportCalls++
	runtime.reportRequest = request
	return runtime.report, runtime.reportErr
}

func TestExecuteFullWorkflowAssessmentReportsPersistedPartialRun(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source.yaml")
	if err := os.WriteFile(source, []byte("spec:\n  inputs:\n    - kind: sj-results\n      path: $workflow.automate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	request := fullWorkflowAssessmentRequest{
		SourceManifestPath:  source,
		ManifestPath:        filepath.Join(directory, "assessment-manifest.yaml"),
		AutomateResultsPath: filepath.Join(directory, "automate.json"),
		OutputDirectory:     directory,
		DatabasePath:        filepath.Join(directory, "assessment.db"),
		PlanPath:            filepath.Join(directory, "assessment-plan.json"),
		RunPath:             filepath.Join(directory, "assessment-run.json"),
		Reports:             fullWorkflowAssessmentReports(directory),
	}
	want := errors.New("assessment completed with partial coverage")
	partial := &assessmentruntime.PartialCoverageError{Cause: want}
	backend := &partialRunAssessmentRuntime{
		fakeAssessmentRuntime: fakeAssessmentRuntime{
			plan:   assessmentruntime.PlanResult{PlanHash: "plan-hash"},
			run:    assessmentruntime.RunResult{AssessmentID: "assessment-partial"},
			report: []byte("sealed partial assessment report"),
		},
		runErr: partial,
	}
	err := executeFullWorkflowAssessment(t.Context(), backend, request)
	if err != nil {
		t.Fatalf("durably reported partial run should be successful: %v", err)
	}
	if backend.reportCalls != len(request.Reports) {
		t.Fatalf("report calls = %d, want %d", backend.reportCalls, len(request.Reports))
	}
	if _, statErr := os.Stat(request.RunPath); statErr != nil {
		t.Fatalf("partial run result was not persisted: %v", statErr)
	}
	for _, report := range request.Reports {
		if _, statErr := os.Stat(report.Path); statErr != nil {
			t.Fatalf("partial assessment report %s was not persisted: %v", report.Format, statErr)
		}
	}

	reportFailure := errors.New("report persistence failed")
	backend.reportErr = reportFailure
	err = executeFullWorkflowAssessment(t.Context(), backend, request)
	if !errors.Is(err, reportFailure) || !errors.Is(err, want) {
		t.Fatalf("partial run with report failure error = %v", err)
	}
}

func fullWorkflowAssessmentReportPaths(reports []fullWorkflowAssessmentReport) []string {
	paths := make([]string, 0, len(reports))
	for _, report := range reports {
		paths = append(paths, report.Path)
	}
	return paths
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
