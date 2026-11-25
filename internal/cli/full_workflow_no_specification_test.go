package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/brute"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/mcpserver"
)

const noSpecificationLine = "No specification URLs found by the brute stage"

// writeBruteResultWithoutSpecifications writes the brute artifacts exactly as
// runBrute writes them in the full workflow (all formats) for targets on
// which nothing was found.
func writeBruteResultWithoutSpecifications(t *testing.T, outfile string, targets []string) {
	t.Helper()
	reports := make([]brute.Report, 0, len(targets))
	for _, target := range targets {
		reports = append(reports, brute.Report{
			Target: target, SpecsFound: []brute.SpecResult{}, Interesting: []brute.Interesting{},
			Summary: brute.Summary{URLsTested: 12, Responses4xx: 12},
		})
	}
	if err := brute.OutputAllFormats(reports, outfile); err != nil {
		t.Fatal(err)
	}
}

func TestExecuteFullWorkflowEndsSuccessfullyWhenBruteFindsNoSpecification(t *testing.T) {
	t.Setenv(assessmentEvidenceKeyEnvironment, strings.Repeat("5a", 32))
	oneTarget := []string{"https://one.example"}
	twoTargets := []string{"https://one.example", "https://two.example"}
	findsNothing := func(targets []string) func(*testing.T, *config.Config) error {
		return func(t *testing.T, stageCfg *config.Config) error {
			writeBruteResultWithoutSpecifications(t, stageCfg.Outfile, targets)
			return nil
		}
	}
	tests := []struct {
		name         string
		targets      []string
		autoAssess   bool
		protocolSafe bool
		brute        func(*testing.T, *config.Config) error
		wantWarning  string
	}{
		{name: "one target writes a report object", targets: oneTarget, brute: findsNothing(oneTarget)},
		{name: "a batch writes a report array", targets: twoTargets, brute: findsNothing(twoTargets)},
		{name: "automatic assessment is skipped too", targets: twoTargets, autoAssess: true, brute: findsNothing(twoTargets)},
		{name: "protocol-safe output", targets: twoTargets, protocolSafe: true, brute: findsNothing(twoTargets)},
		{
			name: "isolated brute target failure keeps its warning", targets: twoTargets,
			brute: func(t *testing.T, stageCfg *config.Config) error {
				writeBruteResultWithoutSpecifications(t, stageCfg.Outfile, twoTargets)
				return brute.NewPartialBatchError(errors.New("scan target 2: open endpoint wordlist: missing"))
			},
			wantWarning: "Brute completed with isolated target failures",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			targets := filepath.Join(directory, "targets.txt")
			if err := os.WriteFile(targets, []byte(strings.Join(test.targets, "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			base := config.New()
			base.DatabasePath = filepath.Join(directory, "sj-results.db")
			var calls []string
			stages := fullWorkflowStages{
				brute: func(_ context.Context, stageCfg *config.Config) error {
					calls = append(calls, "brute")
					return test.brute(t, stageCfg)
				},
				automate: func(ctx context.Context, stageCfg *config.Config) error {
					calls = append(calls, "automate")
					return runAutomate(ctx, stageCfg)
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
			outputDirectory := filepath.Join(directory, "sj-run")
			_, stderr, err := captureCLIStreams(t, func() error {
				return executeFullWorkflow(t.Context(), base, fullWorkflowCLIOptions{
					FullWorkflow: true, TargetsFile: targets, OutputDirectory: outputDirectory,
					Workers: 2, IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
					AutoAssess: test.autoAssess, ProtocolSafeOutput: test.protocolSafe,
				}, stages)
			})
			if err != nil {
				t.Fatalf("a run whose brute stage found no specification failed: %v", err)
			}
			if !reflect.DeepEqual(calls, []string{"brute", "automate"}) {
				t.Fatalf("stages = %v, want brute and automate only", calls)
			}
			wantLine := noSpecificationLine + "; skipped the automate, fuzz, collection, and report stages.\n"
			if test.autoAssess {
				wantLine = noSpecificationLine + "; skipped the automate, fuzz, collection, report, and assessment stages.\n"
			}
			if strings.Count(stderr, wantLine) != 1 {
				t.Fatalf("stderr does not hold the line %q exactly once:\n%s", wantLine, stderr)
			}
			if test.wantWarning != "" && !strings.Contains(stderr, test.wantWarning) {
				t.Fatalf("stderr lost the warning %q:\n%s", test.wantWarning, stderr)
			}
			for _, name := range []string{"automate.json", "fuzz.json"} {
				if _, statErr := os.Lstat(filepath.Join(outputDirectory, name)); !os.IsNotExist(statErr) {
					t.Fatalf("%s exists after a run that found no specification: %v", name, statErr)
				}
			}
		})
	}
}

func TestExecuteFullWorkflowKeepsFailuresThatAreNotAnEmptyBruteResult(t *testing.T) {
	automateFailure := errors.New("automate output could not be written")
	tests := []struct {
		name        string
		urlFile     string
		skipBrute   bool
		bruteRunIDs []string
		brute       func(*testing.T, *config.Config) error
		automate    func(context.Context, *config.Config) error
		wantStages  []string
		wantText    string
		wantIs      error
	}{
		{
			name:    "skip-brute with an earlier brute result naming no specification",
			urlFile: `{"target":"https://one.example","specs_found":[],"summary":{"urls_tested":12}}` + "\n", skipBrute: true,
			wantStages: []string{"automate"}, wantText: "no specification URLs found in", wantIs: errNoSpecificationURLs,
		},
		{
			name: "skip-brute with stored brute runs naming no specification", skipBrute: true, bruteRunIDs: []string{"brute-a"},
			automate: func(_ context.Context, stageCfg *config.Config) error {
				return fmt.Errorf("%w in stored brute runs %v", errNoSpecificationURLs, stageCfg.AutomateRunIDs)
			},
			wantStages: []string{"automate"}, wantText: "no specification URLs found", wantIs: errNoSpecificationURLs,
		},
		{
			name:       "brute result missing",
			brute:      func(*testing.T, *config.Config) error { return nil },
			wantStages: []string{"brute", "automate"}, wantText: "open automate input",
		},
		{
			name: "brute result without specs_found",
			brute: func(t *testing.T, stageCfg *config.Config) error {
				return os.WriteFile(stageCfg.Outfile+".json", []byte(`{"target":"https://one.example","summary":{}}`), 0o600)
			},
			wantStages: []string{"brute", "automate"}, wantText: "does not contain specs_found",
		},
		{
			name: "brute result cut short",
			brute: func(t *testing.T, stageCfg *config.Config) error {
				return os.WriteFile(stageCfg.Outfile+".json", []byte(`{"target":"https://one.example","specs_found":[`), 0o600)
			},
			wantStages: []string{"brute", "automate"}, wantText: "parse brute JSON",
		},
		{
			name: "automate wrote results and still reports no specification",
			brute: func(t *testing.T, stageCfg *config.Config) error {
				writeBruteResultWithoutSpecifications(t, stageCfg.Outfile, []string{"https://one.example"})
				return nil
			},
			automate: func(_ context.Context, stageCfg *config.Config) error {
				if err := os.WriteFile(stageCfg.Outfile+".json", []byte(`{"results":[]}`), 0o600); err != nil {
					return err
				}
				return fmt.Errorf("%w in a later source", errNoSpecificationURLs)
			},
			wantStages: []string{"brute", "automate", "collection", "report"}, wantText: "full workflow automate stage",
			wantIs: errNoSpecificationURLs,
		},
		{
			name: "automate fails for another reason",
			brute: func(t *testing.T, stageCfg *config.Config) error {
				writeBruteResultWithoutSpecifications(t, stageCfg.Outfile, []string{"https://one.example"})
				return nil
			},
			automate:   func(context.Context, *config.Config) error { return automateFailure },
			wantStages: []string{"brute", "automate"}, wantText: "full workflow automate stage", wantIs: automateFailure,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			base := config.New()
			base.DatabasePath = filepath.Join(directory, "sj-results.db")
			targets := ""
			if len(test.bruteRunIDs) == 0 {
				targets = filepath.Join(directory, "targets.txt")
				contents := test.urlFile
				if contents == "" {
					contents = "https://one.example\n"
				}
				if err := os.WriteFile(targets, []byte(contents), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var calls []string
			stages := fullWorkflowStages{
				brute: func(_ context.Context, stageCfg *config.Config) error {
					calls = append(calls, "brute")
					return test.brute(t, stageCfg)
				},
				automate: func(ctx context.Context, stageCfg *config.Config) error {
					calls = append(calls, "automate")
					if test.automate != nil {
						return test.automate(ctx, stageCfg)
					}
					return runAutomate(ctx, stageCfg)
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
			}
			_, _, err := captureCLIStreams(t, func() error {
				return executeFullWorkflow(t.Context(), base, fullWorkflowCLIOptions{
					FullWorkflow: true, SkipBrute: test.skipBrute, TargetsFile: targets, BruteRunIDs: test.bruteRunIDs,
					OutputDirectory: filepath.Join(directory, "sj-run"),
					Workers:         1, IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
				}, stages)
			})
			if err == nil {
				t.Fatal("workflow succeeded")
			}
			if !strings.Contains(err.Error(), test.wantText) {
				t.Fatalf("error = %v, want it to contain %q", err, test.wantText)
			}
			if test.wantIs != nil && !errors.Is(err, test.wantIs) {
				t.Fatalf("error = %v, want errors.Is %v", err, test.wantIs)
			}
			if !reflect.DeepEqual(calls, test.wantStages) {
				t.Fatalf("stages = %v, want %v", calls, test.wantStages)
			}
		})
	}
}

func TestLoadAutomateURLsReportsNoSpecificationWithTypedError(t *testing.T) {
	reports := []brute.Report{{Target: "https://one.example", SpecsFound: []brute.SpecResult{}}}
	directory := t.TempDir()
	path := filepath.Join(directory, "brute")
	if err := brute.OutputAllFormats(reports, path); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"brute.json", "brute.jsonl", "brute.txt"} {
		t.Run(name, func(t *testing.T) {
			input := filepath.Join(directory, name)
			_, err := loadAutomateURLs(input, 1<<20, 10)
			if !errors.Is(err, errNoSpecificationURLs) {
				t.Fatalf("error = %v, want errNoSpecificationURLs", err)
			}
			if want := `no specification URLs found in "` + input + `"`; err.Error() != want {
				t.Fatalf("error text = %q, want %q", err.Error(), want)
			}
		})
	}
}

func TestExecuteMCPFullWorkflowCompletesWhenBruteFindsNoSpecification(t *testing.T) {
	root := t.TempDir()
	commandConfig := config.New()
	commandConfig.DatabasePath = filepath.Join(root, "results.db")
	targets := []string{"https://one.example", "https://two.example"}
	stages := fullWorkflowStages{
		brute: func(_ context.Context, stageCfg *config.Config) error {
			writeBruteResultWithoutSpecifications(t, stageCfg.Outfile, targets)
			return nil
		},
		automate: runAutomate,
		fuzz: func(context.Context, *config.Config, fuzzCLIOptions) error {
			t.Fatal("fuzz ran")
			return nil
		},
		collection: func(context.Context, *config.Config, collectionCLIOptions) error {
			t.Fatal("collection ran")
			return nil
		},
		report: func(context.Context, *config.Config, reportCLIOptions) error {
			t.Fatal("report ran")
			return nil
		},
		assessment: func(context.Context, *config.Config, fullWorkflowAssessmentRequest) error {
			t.Fatal("assessment ran")
			return nil
		},
	}
	var result mcpserver.FullWorkflowOutput
	_, _, err := captureCLIStreams(t, func() error {
		var runErr error
		result, runErr = executeMCPFullWorkflow(t.Context(), commandConfig, mcpserver.FullWorkflowRequest{
			Targets: targets, OutputDirectory: filepath.Join(root, "run"), Workers: 2, IDORRange: "1-2",
			MaxFuzzRequests: 128, MaxCases: 128, Delay: 100 * time.Millisecond, MaxEvidence: 10, AutoAssess: true,
		}, []byte(strings.Repeat("a", 32)), stages)
		return runErr
	})
	if err != nil {
		t.Fatalf("MCP full workflow failed when brute found no specification: %v", err)
	}
	if !result.Completed || result.AssessmentID != "" {
		t.Fatalf("result = %#v", result)
	}
	want := []string{"assessment-manifest.yaml", "brute.csv", "brute.json", "brute.jsonl", "brute.txt"}
	if !reflect.DeepEqual(result.Artifacts, want) {
		t.Fatalf("artifacts = %v, want %v", result.Artifacts, want)
	}
}

// TestFullWorkflowWithRealStagesEndsWhenNothingIsFound runs the default stages,
// as CASM invokes them (database beside the run directory, automatic
// assessment), against a local server that answers 404 to every request.
func TestFullWorkflowWithRealStagesEndsWhenNothingIsFound(t *testing.T) {
	t.Setenv(assessmentEvidenceKeyEnvironment, strings.Repeat("5a", 32))
	server := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	for _, protocolSafe := range []bool{false, true} {
		name := "console output"
		if protocolSafe {
			name = "protocol-safe output"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			targets := filepath.Join(root, "targets.txt")
			if err := os.WriteFile(targets, []byte(server.URL+"\n"+server.URL+"/v1\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			wordlist := filepath.Join(root, "wordlist.txt")
			if err := os.WriteFile(wordlist, []byte("openapi.json\nswagger.json\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			base := config.New()
			base.Quiet = true
			base.DatabasePath = filepath.Join(root, "sj-results.db")
			base.EndpointWordlist = wordlist
			base.MaxCandidates = 10
			outputDirectory := filepath.Join(root, "sj-run")
			_, stderr, err := captureCLIStreams(t, func() error {
				return executeFullWorkflow(t.Context(), base, fullWorkflowCLIOptions{
					FullWorkflow: true, TargetsFile: targets, OutputDirectory: outputDirectory,
					Workers: 2, IDORRange: "1-100", MaxFuzzRequests: 20_000, MaxCases: 4_096,
					Delay: 500 * time.Millisecond, MaxEvidence: 100, AutoAssess: true,
					EnableSpecialCharsFuzz: true, ProtocolSafeOutput: protocolSafe,
				}, defaultFullWorkflowStages())
			})
			if err != nil {
				t.Fatalf("full workflow failed when nothing was found: %v\n%s", err, stderr)
			}
			if !strings.Contains(stderr, noSpecificationLine) {
				t.Fatalf("stderr does not report the outcome:\n%s", stderr)
			}
			entries, err := os.ReadDir(outputDirectory)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, entry := range entries {
				names = append(names, entry.Name())
			}
			sort.Strings(names)
			want := []string{"assessment-manifest.yaml", "brute.csv", "brute.json", "brute.jsonl", "brute.txt"}
			if !slices.Equal(names, want) {
				t.Fatalf("output directory = %v, want %v", names, want)
			}
			jsonl, err := os.ReadFile(filepath.Join(outputDirectory, "brute.jsonl"))
			if err != nil || len(jsonl) != 0 {
				t.Fatalf("brute.jsonl = %q (%v), want empty", jsonl, err)
			}
			_, err = loadAutomateURLs(filepath.Join(outputDirectory, "brute.json"), 1<<20, 10)
			if !errors.Is(err, errNoSpecificationURLs) {
				t.Fatalf("brute.json does not read as a result that found nothing: %v", err)
			}
		})
	}
}
